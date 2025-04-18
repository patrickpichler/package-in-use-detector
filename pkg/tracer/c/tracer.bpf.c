#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_kfuncs.h"
#include "types.h"
#include "jhash.h"

#define MAX_NUM_MOUNT_NS  1024
#define MAX_FILES_TRACKED 8192

#define MAX_STRINGS    32768
#define MAX_STRING_LEN 252

#define BUF_SIZE 1024

struct config {
  u32 current_file_access_idx;
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
  union {
    u8 str[MAX_STRING_LEN];
    u32 str_ints[MAX_STRING_LEN / sizeof(u32)];
  };
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
  u32 hash;
};

struct file_value {
  struct file_path path;
  u32 collision_counter;
  // TODO(patrick.pichler): some statistics might be interesting, but for now this is fine.
  u8 ignored;
};

#define MAX_FILES 65535

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FILES);
  __type(key, struct file_key);
  __type(value, struct file_value);
} files SEC(".maps");

struct inode_key {
  u32 ino;
  u32 dev;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_FILES);
  __type(key, struct inode_key);
  __type(value, u32);
} inode_file_cache SEC(".maps");

#define MAX_IGNORED_PATHS 1024

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_IGNORED_PATHS);
  __type(key, struct file_path);
  __type(value, u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} ignored_paths SEC(".maps");

#define MAX_FILE_ACCESS 65535

struct file_access_key {
  u64 cgroup_id;
  u32 file_id;
};

struct file_access_value {
  u8 counter;
};

// Required to force BTF creation.
struct file_access_key unusd_file_access_key __attribute__((unused));
struct file_access_value unusd_file_access_val __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(max_entries, 2);
  __type(key, u32);
  __array(
    values, struct {
      __uint(type, BPF_MAP_TYPE_LRU_HASH);
      __uint(max_entries, MAX_FILE_ACCESS);
      __type(key, struct file_access_key);
      __type(value, struct file_access_value);
    });
} file_access_buffer_map SEC(".maps");

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
  __type(value, struct dentry *[MAX_PATH_COMPONENTS]);
} file_path_scratch SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct file_value);
} file_value_scratch SEC(".maps");

static __always_inline u32 can_inline(struct string_value *str)
{
  bool less_than_four_chars = false;

#pragma unroll
  for (int i = 0; i < 5; i++) {
    if (str->str[i] == 0) {
      less_than_four_chars = true;
      break;
    }
  }

  // We cannot inline values with the MSB in the fourth char set, as this bit
  // is used to mark if the id is inlined or not.
  if (less_than_four_chars && str->str[0] & 1 << 7) {
    bpf_printk("cannot inline since forth str is %d", str->str[3]);
    return 0;
  }

  return less_than_four_chars;
}

static __always_inline u32 get_file_id(struct file_value *val)
{
  struct file_key key = {0};

  key.hash = jenkins_one_at_a_time(val->path.parts, sizeof(val->path.parts));

  if (bpf_map_update_elem(&files, &key, val, BPF_NOEXIST)) {
    struct file_value *existing = bpf_map_lookup_elem(&files, &key);
    if (existing) {
#pragma unroll
      for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        // collision found
        if (val->path.parts[i] != existing->path.parts[i]) {
          barrier();
          __sync_fetch_and_add(&existing->collision_counter, 1);
          break;
        }
        // No need to compare anything after the null termination, as the string ended.
        if (val->path.parts[i] == 0) {
          break;
        }
      }
    }
  }

  return key.hash;
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

  __builtin_memset(val->str, 0, sizeof(val->str));

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

  bool debug = false;

  debug = str_len == 13 && val->str[0] == 'k' && val->str[1] == 'u' && val->str[2] == 'b';

  struct string_key key = {0};

  key.hash = jenkins_one_at_a_time(val->str, str_len);

  key.hash |= bpf_htonl(1L << 31);

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
  u32 zero = 0;
  struct dentry **parts;
  char name[255];
  int current = MAX_PATH_COMPONENTS - 1;

  parts = bpf_map_lookup_elem(&file_path_scratch, &zero);
  if (!parts) {
    return 0;
  }

  __builtin_memset(parts, 0, sizeof(parts) * MAX_PATH_COMPONENTS);

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

    parts[current] = dentry;
    dentry = d_parent;

    if (current == 0) {
      return 0;
    }

    current--;
  }

  if (current == MAX_PATH_COMPONENTS) {
    return 0;
  }

  u8 parts_idx = current + 1;

  for (u8 i = 0; i < MAX_PATH_COMPONENTS; i++) {
    if (parts_idx >= MAX_PATH_COMPONENTS) {
      break;
    }

    if (i == current) {
      break;
    }

    struct dentry *dentry = parts[parts_idx++];

    // Add this dentry name to path
    BPF_CORE_READ_INTO(&d_name, dentry, d_name);

    u32 id = get_string_id(d_name);
    if (!id) {
      bpf_printk("no id");
      // Something is broken and we cannot get the ID
      return 0;
    }

    out->parts[i] = id;

    if (bpf_map_lookup_elem(&ignored_paths, out)) {
      return 2;
    }
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
  struct inode_key ino_key = {0};

  if (BPF_CORE_READ_INTO(&ino_key.ino, file, f_inode, i_ino)) {
    return 0;
  }

  if (BPF_CORE_READ_INTO(&ino_key.dev, file, f_inode, i_sb, s_dev)) {
    return 0;
  }

  if (!ino_key.ino) {
    return 0;
  }

  struct path path;
  struct file_access_key key = {0};
  struct file_value *f_val;
  u32 zero = 0;
  u32 *cached_file_id = 0;

  // Inode cache is not optimal to use, as there can be different names for inodes.
  // E.g. in the cgroups fs, the cgroup folder has the same inode as the cgroup it represents,
  // also hardlinks exist.
  // TODO(patrick.pichler): think about a better approach to this
  cached_file_id = bpf_map_lookup_elem(&inode_file_cache, &ino_key);
  if (cached_file_id) {
    struct file_key f_key = {.hash = *cached_file_id};
    f_val = bpf_map_lookup_elem(&files, &f_key);
    // TODO(patrick.pichler): handle this case better by recomputing
    if (!f_val) {
      bpf_printk("cache is pointing to dead file val");
      return 0;
    }

    key.file_id = f_key.hash;
  } else {
    f_val = bpf_map_lookup_elem(&file_value_scratch, &zero);
    if (!f_val) {
      bpf_printk("cannot get file scratch");
      return 0;
    }

    __builtin_memset(&f_val->path, 0, sizeof(f_val->path));

    BPF_CORE_READ_INTO(&path, file, f_path);

    int res = get_path(&path, &f_val->path);
    if (!res) {
      bpf_printk("cannot get filepath");
      return 0;
    }

    // TODO(patrick.pichler): this is currently not concerned with updating already existing
    // files and set them to ignored. It is fine for now, but needs to be handled later.
    if (res == 2) {
      f_val->ignored = 1;
    }

    u32 f_id = get_file_id(f_val);
    if (!f_id) {
      bpf_printk("cannot get file id");
      return 0;
    }

    bpf_map_update_elem(&inode_file_cache, &ino_key, &f_id, BPF_ANY);

    key.file_id = f_id;
  }

  key.cgroup_id = bpf_get_current_cgroup_id();

  struct config *config = bpf_map_lookup_elem(&config_map, &zero);
  if (!config)
    return 0;

  void *file_access_map =
    bpf_map_lookup_elem(&file_access_buffer_map, &config->current_file_access_idx);
  if (!file_access_map) {
    return 0;
  }

  struct file_access_value counter = {0};

  bpf_map_update_elem(file_access_map, &key, &counter, BPF_ANY);

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
