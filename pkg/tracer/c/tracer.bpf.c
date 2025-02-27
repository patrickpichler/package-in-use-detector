#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_kfuncs.h"
#include "types.h"

#define MAX_NUM_MOUNT_NS 1024
#define MAX_FILES_TRACKED 8192

#define MAX_STRINGS 32768
#define MAX_STRING_LEN 255

struct config {
  u64 next_string_id;
  u64 max_reached;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct config);
} config_map SEC(".maps");

struct string_key {
  char str[MAX_STRING_LEN];
};

struct string_value {
  u32 id;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_STRINGS);
  __type(key, struct string_key);
  __type(value, struct string_value);
} strings SEC(".maps");

struct file_access_prefix_key {};
struct file_access_prefix_value {};

struct file_access_key {
  u32 mnt_ns;
  pid_t pid;
  dev_t dev;
  u64 i_nu;
};
struct file_access {};

static __always_inline int can_inline(struct string_key *key) {
  // We cannot inline values with the MSB in the first char set, as this bit
  // is used to mark if the id is inlined or not.
  if (key->str[0] & 0x100) {
    bpf_printk("cannot inline since first str is %d", key->str[0]);
    return 0;
  }

#pragma unroll
  for (int i = 0; i < 5; i++) {
    if (key->str[i] == '\0') {
      return 1;
    }
  }

  return 0;
}

static __always_inline u32 find_id(struct string_key *key) {
  if (can_inline(key)) {
    u32 id = 0;
    __builtin_memcpy(&id, &key->str, 4);
    return id;
  }

  struct string_value *val;

  val = bpf_map_lookup_elem(&strings, key);
  u64 id;

  if (!val) {
    u32 zero = 0;
    struct config *c = bpf_map_lookup_elem(&config_map, &zero);
    if (!c) {
      bpf_printk("no config");
      return 0;
    }
    if (c->max_reached) {
      bpf_printk("max reached");
      return 0;
    }

    barrier();
    __sync_fetch_and_add(&c->next_string_id, 1);
    id = c->next_string_id;
    // TODO(patrick.pichler): figure out why atomic operations do not work.
    // Return value cannot be assigned and is causing this error
    //  > BPF_STX uses reserved fields
    // id = __sync_fetch_and_add(&c->next_string_id, 1);
    barrier();
    if (id & 0x100000000) {
      __sync_fetch_and_add(&c->max_reached, 1);
      bpf_printk("max id reached");
      return 0;
    }

    if (bpf_map_update_elem(&strings, key, &id, BPF_NOEXIST)) {
      // Most like due to race condition
      val = bpf_map_lookup_elem(&strings, key);
      if (val) {
        id = val->id;
      } else {
        bpf_printk("no val");
        // Some error we cannot recover from;
        return 0;
      }
    }
  } else {
    id = val->id;
  }

  return id;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(security_file_open, struct file *file) {
  char *filename;
  u32 filename_len;
  // TODO(patrick.pichler): put this in a staging buffer to not take up stack
  // space
  struct string_key key = {0};

  if (BPF_CORE_READ_INTO(&filename, file, f_path.dentry, d_name.name)) {
    // There is nothing we can do on failure.
    return 0;
  }

  if (BPF_CORE_READ_INTO(&filename_len, file, f_path.dentry, d_name.len)) {
    // There is nothing we can do on failure.
    return 0;
  }

  if (filename_len > MAX_STRING_LEN) {
    // This is more of a theoretical case, but to make the verifier happy.
    filename_len = MAX_STRING_LEN;
  }

  if (bpf_core_read(&key.str, filename_len, filename)) {
    // There is nothing we can do on failure.
    return 0;
  }

  u64 id = find_id(&key);

  bpf_printk("id for %s is %d", key.str, id);

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
