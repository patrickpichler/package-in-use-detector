#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_kfuncs.h"
#include "types.h"
#include "xxhash.h"
#include "fasthash.h"

#define MAX_NUM_MOUNT_NS  1024
#define MAX_FILES_TRACKED 8192

#define MAX_STRINGS    32768
#define MAX_STRING_LEN 255

#define BUF_SIZE 1024

struct config {
  u64 current_string_id;
  u64 max_string_reached;

  u64 current_file_id;
  u64 max_file_reached;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct config);
} config_map SEC(".maps");

struct string_key {
  u32 hash;
};

struct string_value {
  char str[MAX_STRING_LEN];
  u32 collision_counter;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_STRINGS);
  __type(key, struct string_key);
  __type(value, struct string_value);
} strings SEC(".maps");

#define MAX_PATH_COMPONENTS 16

struct file_path {
  u32 parts[MAX_PATH_COMPONENTS];
};

struct file_key {
  struct file_path path;
};

struct file_value {
  u32 id;
};

#define MAX_FILES 65535

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FILES);
  __type(key, struct file_key);
  __type(value, struct file_value);
} files SEC(".maps");

#define MAX_FILE_ACCESS 65535

struct file_access_key {
  u32 mnt_ns;
  pid_t pid;
  u64 process_start_time;
  u32 file_id;
};

struct file_access_value {
  u8 counter;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FILE_ACCESS);
  __type(key, struct file_access_key);
  __type(value, struct file_access_value);
} file_access SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct string_value);
} string_value_scratch SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u32[MAX_PATH_COMPONENTS]);
} file_path_scratch SEC(".maps");

static __always_inline u32 can_inline(struct string_value *str)
{
  bool less_than_four_chars = false;

#pragma unroll
  for (int i = 0; i < 5; i++) {
    if (str->str[i] == '\0') {
      less_than_four_chars = true;
      break;
    }
  }

  // We cannot inline values with the MSB in the fourth char set, as this bit
  // is used to mark if the id is inlined or not.
  if (less_than_four_chars && str->str[3] & 1 << 7) {
    bpf_printk("cannot inline since forth str is %d", str->str[3]);
    return 0;
  }

  return less_than_four_chars;
}

static __always_inline u32 find_file_id(struct file_key *key)
{
  struct file_value *val;

  val = bpf_map_lookup_elem(&files, key);

  if (!val) {
    u64 id;
    u32 zero = 0;
    struct config *c = bpf_map_lookup_elem(&config_map, &zero);
    if (!c) {
      bpf_printk("no config");
      return 0;
    }
    if (c->max_file_reached) {
      bpf_printk("max file reached");
      return 0;
    }

    barrier();
    __sync_fetch_and_add(&c->current_file_id, 1);
    id = c->current_file_id;
    // TODO(patrick.pichler): figure out why atomic operations do not work.
    // Return value cannot be assigned and is causing this error
    //  > BPF_STX uses reserved fields
    // id = __sync_fetch_and_add(&c->next_string_id, 1);
    barrier();

    // If we ever reach a value that can no longer expressed via u32, the IDs are full and we
    // can only abort.
    if (id & 0x200000000) {
      __sync_fetch_and_add(&c->max_file_reached, 1);
      bpf_printk("max file id reached");
      return 0;
    }

    if (bpf_map_update_elem(&files, key, &id, BPF_NOEXIST)) {
      // Most like due to race condition
      val = bpf_map_lookup_elem(&files, key);
      if (val) {
        return val->id;
      } else {
        bpf_printk("no file val");
        // Some error we cannot recover from;
        return 0;
      }
    } else {
      return id;
    }
  } else {
    return val->id;
  }

  return 0;
}

static __always_inline u32 get_string_id(struct qstr str)
{
  // TODO(patrick.pichler): key should probably be passed in as argument to be
  // reused.
  u32 zero = 0;
  struct string_value *val = bpf_map_lookup_elem(&string_value_scratch, &zero);
  if (!val) {
    return 0;
  }

  __builtin_memset(val->str, 0, 255);

  u32 str_len = str.len;

  if (str_len > MAX_STRING_LEN) {
    str_len = MAX_STRING_LEN;
  }

  if (bpf_core_read(&val->str, str_len, str.name)) {
    // There is nothing we can do on failure.
    return 0;
  }

  if (can_inline(val)) {
    u32 id = 0;
    __builtin_memcpy(&id, &val->str, 4);
    return id;
  }

  struct string_key key = {0};

  // TODO(patrick.pichler): benchmark if this brings any performance boost over just
  // just calculating the has over the full buffer.
  switch (str_len) {
    case 0 ... 32:
      key.hash = fasthash32(val->str, 32, 0);
      break;
    case 33 ... 64:
      key.hash = fasthash32(val->str, 64, 0);
      break;
    case 65 ... 128:
      key.hash = fasthash32(val->str, 128, 0);
      break;
    default:
      key.hash = fasthash32(val->str, sizeof(val->str), 0);
      break;
  }

  if (bpf_map_update_elem(&strings, &key, val, BPF_NOEXIST)) {
    struct string_value *existing = bpf_map_lookup_elem(&strings, &key);
    if (existing) {
#pragma unroll
      for (int i = 0; i < sizeof(val->str); i++) {
        // collision found
        if (val->str[i] != existing->str[i]) {
          barrier();
          __sync_fetch_and_add(&existing->collision_counter, 1);
          break;
        }
        // No need to compare anything after the null termination, as the string ended.
        if (val->str[i] == '\0') {
          break;
        }
      }
    }
  }

  return key.hash;
}

static __always_inline int get_path(struct path *path, struct file_path *out)
{
  struct path f_path;
  bpf_probe_read_kernel(&f_path, sizeof(struct path), path);
  struct dentry *dentry = f_path.dentry;
  struct vfsmount *vfsmnt = f_path.mnt;
  struct mount *mnt_parent_p;
  struct mount *mnt_p = container_of(vfsmnt, struct mount, mnt);
  bpf_core_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
  struct dentry *mnt_root;
  struct dentry *d_parent;
  struct qstr d_name;
  int sz;
  int current = 0;
  u32 zero = 0;
  u32 *parts;
  char name[255];

  parts = bpf_map_lookup_elem(&file_path_scratch, &zero);
  if (!parts) {
    return 0;
  }

  __builtin_memset(parts, 0, 32);

#pragma unroll
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
    BPF_CORE_READ_INTO(&mnt_root, // NOLINT(bugprone-sizeof-expression)
                       vfsmnt, mnt_root);
    BPF_CORE_READ_INTO(&d_parent, // NOLINT(bugprone-sizeof-expression)
                       dentry, d_parent);

    if (dentry == mnt_root || dentry == d_parent) {
      if (dentry != mnt_root) {
        // We reached root, but not mount root - escaped?
        break;
      }
      if (mnt_p != mnt_parent_p) {
        BPF_CORE_READ_INTO(&dentry, // NOLINT(bugprone-sizeof-expression)
                           mnt_p, mnt_mountpoint);
        BPF_CORE_READ_INTO(&mnt_p, // NOLINT(bugprone-sizeof-expression)
                           mnt_p, mnt_parent);
        BPF_CORE_READ_INTO(&mnt_parent_p, // NOLINT(bugprone-sizeof-expression)
                           mnt_p, mnt_parent);
        vfsmnt = &mnt_p->mnt;
        continue;
      }

      // Global root - path fully parsed
      break;
    }

    // Add this dentry name to path
    BPF_CORE_READ_INTO(&d_name, dentry, d_name);

    u32 id = get_string_id(d_name);

    if (!id) {
      bpf_printk("no id");
      // Something is broken and we cannot get the ID
      return 0;
    }

    if (current > MAX_PATH_COMPONENTS) {
      return 0;
    }

    parts[current] = id;
    dentry = d_parent;
    current++;
  }

  if (current == 0 || current == MAX_PATH_COMPONENTS) {
    return 0;
  }

  for (int i = 0; i < current; i++) {
    out->parts[current - i - 1] = parts[i];
  }

  // memfd files have no path in the filesystem -> extract their name
  // if (current == 0) {
  // TODO(patrick.pichler): implement
  // }

  return 1;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(security_file_open, struct file *file)
{
  struct path path;
  struct file_access_key key = {0};
  struct file_key f_key = {};

  BPF_CORE_READ_INTO(&path, file, f_path);

  if (!get_path(&path, &f_key.path)) {
    bpf_printk("cannot get filepath");
    return 0;
  }

  u32 f_id = find_file_id(&f_key);
  if (!f_id) {
    bpf_printk("cannot get file id");
    return 0;
  }

  key.file_id = f_id;

  struct task_struct *t = (void *) bpf_get_current_task();

  BPF_CORE_READ_INTO(&key.pid, t, pid);
  BPF_CORE_READ_INTO(&key.process_start_time, t, start_time);

  struct file_access_value counter = {0};

  bpf_map_update_elem(&file_access, &key, &counter, BPF_ANY);

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
