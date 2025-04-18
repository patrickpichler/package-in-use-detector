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

#define MAX_PATH      (1 << 9)
#define MAX_PATH_MASK (1 << 9) - 1

struct file_path {
  u8 path[MAX_PATH];
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

static __attribute__((aligned(8))) u32 empty[MAX_PATH * 2] = {0};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  // HACK(patrick.pichler): We sadly need to waste a bit of memory to make the verifier happy. The
  // reason being that the verifier cannot keep track of the buffer access sizes when reading
  // strings from dentries. It always thinks we are reading after memory limit. To solve this, the
  // buffer now is simply twice the size of the max path len. This way all memory operations will
  // for sure stay within the buffer.
  __type(value, u8[MAX_PATH * 2]);
} file_path_scratch SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct file_value);
} file_value_scratch SEC(".maps");

static __always_inline u32 get_file_id(struct file_value *val)
{
  struct file_key key = {0};
  u8 zero = 0;
  struct config *cfg;
  u32 id = 0;

  cfg = bpf_map_lookup_elem(&config_map, &key);
  if (!cfg) {
    return 0;
  }

  key.hash = jenkins_one_at_a_time(val->path.path, sizeof(val->path.path));

  if (bpf_map_update_elem(&files, &key, val, BPF_NOEXIST)) {
    struct file_value *existing = bpf_map_lookup_elem(&files, &key);
    if (existing) {
#pragma unroll
      for (int i = 0; i < MAX_PATH; i++) {
        // collision found
        if (val->path.path[i] != existing->path.path[i]) {
          barrier();
          __sync_fetch_and_add(&existing->collision_counter, 1);
          break;
        }
        // No need to compare anything after the null termination, as the string ended.
        if (val->path.path[i] == 0) {
          break;
        }
      }
    }
  }

  return key.hash;
}

#define MAX_PATH_COMPONENTS 16

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
  struct qstr d_name = {0};
  u32 zero = 0;
  u32 len = 0;
  u8 *buf;
  // The last value in the buffer should always be '\0'
  u32 off = MAX_PATH - 1;

  buf = bpf_map_lookup_elem(&file_path_scratch, &zero);
  if (!buf) {
    return 0;
  }

  // We only ever use up to MAX_PATH, hence we only clear the those values. Since
  // eBPF ARRAY maps are zeroed out by default, there is no need to clear anything
  // after MAX_PATH.
  // __builtin_memset(buf, 0, MAX_PATH);

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

    if (BPF_CORE_READ_INTO(&d_name, dentry, d_name)) {
      return 1;
    }

    // The +1 is for the additional slash thas is required.
    off -= (d_name.len & MAX_PATH_MASK) + 1;

    if (off > MAX_PATH - 1) {
      // String overflowed
      return 2;
    }

    if (!d_name.name) {
      return 3;
    }

    len = d_name.len & MAX_PATH_MASK;
    if (len > MAX_PATH - 1) {
      return 3;
    }

    bpf_core_read(&buf[(off + 1) & MAX_PATH_MASK], len, d_name.name);
    buf[off & MAX_PATH_MASK] = '/';

    dentry = d_parent;
  }

  bpf_probe_read_kernel_str(out->path, MAX_PATH, buf + off);

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
