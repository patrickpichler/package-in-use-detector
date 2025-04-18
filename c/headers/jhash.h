#ifndef _LINUX_JHASH_H
#define _LINUX_JHASH_H

// We use the same hash file from go fuzzer to test if the go version of the hashing algo
// works the same.
#ifdef __GOLANG_TEST
typedef unsigned int __u32;
typedef unsigned char __u8;
  #define DEBUG(str, args...)
#else
  #include <vmlinux.h>
  #include <bpf/bpf_helpers.h>
#endif

#define MAX_HASH_LEN 255

static inline __u32 jenkins_one_at_a_time(const void *k, __u32 len)
{
  const __u8 *key = k;
  __u32 hash = 0;

  for (int i = 0; i < MAX_HASH_LEN; i += 1) {
    if (i >= len || key[i] == 0) {
      break;
    }

    hash += key[i];
    hash += (hash << 10);
    hash ^= (hash >> 6);
  }

  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  return hash;
}

#endif /* _LINUX_JHASH_H */
