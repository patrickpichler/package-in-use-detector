#ifndef _LINUX_JHASH_H
#define _LINUX_JHASH_H

#include "types.h"
#include "bpf/bpf_helpers.h"

/* Copied from $(LINUX)/include/linux/jhash.h (kernel 4.18) */

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 */

static __always_inline u32 rol32(u32 word, unsigned int shift)
{
  return (word << shift) | (word >> ((-shift) & 31));
}

/* copy paste of jhash from kernel sources (include/linux/jhash.h) to make sure
 * LLVM can compile it into valid sequence of BPF instructions
 */
#define __jhash_mix(a, b, c)                                                                       \
  {                                                                                                \
    a -= c;                                                                                        \
    a ^= rol32(c, 4);                                                                              \
    c += b;                                                                                        \
    b -= a;                                                                                        \
    b ^= rol32(a, 6);                                                                              \
    a += c;                                                                                        \
    c -= b;                                                                                        \
    c ^= rol32(b, 8);                                                                              \
    b += a;                                                                                        \
    a -= c;                                                                                        \
    a ^= rol32(c, 16);                                                                             \
    c += b;                                                                                        \
    b -= a;                                                                                        \
    b ^= rol32(a, 19);                                                                             \
    a += c;                                                                                        \
    c -= b;                                                                                        \
    c ^= rol32(b, 4);                                                                              \
    b += a;                                                                                        \
  }

#define __jhash_final(a, b, c)                                                                     \
  {                                                                                                \
    c ^= b;                                                                                        \
    c -= rol32(b, 14);                                                                             \
    a ^= c;                                                                                        \
    a -= rol32(c, 11);                                                                             \
    b ^= a;                                                                                        \
    b -= rol32(a, 25);                                                                             \
    c ^= b;                                                                                        \
    c -= rol32(b, 16);                                                                             \
    a ^= c;                                                                                        \
    a -= rol32(c, 4);                                                                              \
    b ^= a;                                                                                        \
    b -= rol32(a, 14);                                                                             \
    c ^= b;                                                                                        \
    c -= rol32(b, 24);                                                                             \
  }

#define JHASH_INITVAL 0xdeadbeef

typedef unsigned int u32;

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */
static __always_inline u32 jhash(const void *key, u8 length, u32 initval)
{
  u32 a, b, c;
  const unsigned char *k = key;

  /* Set up the internal state */
  a = b = c = JHASH_INITVAL + length + initval;

  /* All but the last block: affect some 32 bits of (a,b,c) */
  while (length > 12) {
    a += *(u32 *) (k);
    b += *(u32 *) (k + 4);
    c += *(u32 *) (k + 8);
    __jhash_mix(a, b, c);
    length -= 12;
    k += 12;
  }
  /* Last block: affect all 32 bits of (c) */
  switch (length) {
    case 12:
      c += (u32) k[11] << 24; /* fall through */
    case 11:
      c += (u32) k[10] << 16; /* fall through */
    case 10:
      c += (u32) k[9] << 8; /* fall through */
    case 9:
      c += k[8]; /* fall through */
    case 8:
      b += (u32) k[7] << 24; /* fall through */
    case 7:
      b += (u32) k[6] << 16; /* fall through */
    case 6:
      b += (u32) k[5] << 8; /* fall through */
    case 5:
      b += k[4]; /* fall through */
    case 4:
      a += (u32) k[3] << 24; /* fall through */
    case 3:
      a += (u32) k[2] << 16; /* fall through */
    case 2:
      a += (u32) k[1] << 8; /* fall through */
    case 1:
      a += k[0];
      __jhash_final(a, b, c);
    case 0: /* Nothing left to add */
      break;
  }

  return c;
}

/**
 * This version of jhash will stop hashing on the first encountered null byte
 * in a part.
 **/
static __always_inline u32 jhash_optimized(const void *key, u8 length, u32 initval)
{
  u32 a, b, c;
  const unsigned char *k = key;

  /* Set up the internal state */
  a = b = c = JHASH_INITVAL + length + initval;

  /* All but the last block: affect some 32 bits of (a,b,c) */
  while (length > 12 && *k != 0) {
    a += *(u32 *) (k);
    b += *(u32 *) (k + 4);
    c += *(u32 *) (k + 8);
    __jhash_mix(a, b, c);
    length -= 12;
    k += 12;
  }

  // Exit on first encountered null byte.
  if (*k == 0) {
    return c;
  }

  /* Last block: affect all 32 bits of (c) */
  switch (length) {
    case 12:
      c += (u32) k[11] << 24; /* fall through */
    case 11:
      c += (u32) k[10] << 16; /* fall through */
    case 10:
      c += (u32) k[9] << 8; /* fall through */
    case 9:
      c += k[8]; /* fall through */
    case 8:
      b += (u32) k[7] << 24; /* fall through */
    case 7:
      b += (u32) k[6] << 16; /* fall through */
    case 6:
      b += (u32) k[5] << 8; /* fall through */
    case 5:
      b += k[4]; /* fall through */
    case 4:
      a += (u32) k[3] << 24; /* fall through */
    case 3:
      a += (u32) k[2] << 16; /* fall through */
    case 2:
      a += (u32) k[1] << 8; /* fall through */
    case 1:
      a += k[0];
      __jhash_final(a, b, c);
    case 0: /* Nothing left to add */
      break;
  }

  return c;
}

/* jhash2 - hash an array of u32's
 * @k: the key which must be an array of u32's
 * @length: the number of u32's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static __always_inline u32 jhash2(const u32 *k, u8 length, u32 initval)
{
  u32 a, b, c;

  /* Set up the internal state */
  a = b = c = JHASH_INITVAL + (length << 2) + initval;

  /* Handle most of the key */
  while (length > 3) {
    a += k[0];
    b += k[1];
    c += k[2];
    __jhash_mix(a, b, c);
    length -= 3;
    k += 3;
  }

  /* Handle the last 3 u32's */
  switch (length) {
    case 3:
      c += k[2]; /* fall through */
    case 2:
      b += k[1]; /* fall through */
    case 1:
      a += k[0];
      __jhash_final(a, b, c);
    case 0: /* Nothing left to add */
      break;
  }

  return c;
}

static __always_inline u32 jhash2_optimized(const u32 *k, u8 length, u32 initval)
{
  u32 a, b, c;

  /* Set up the internal state */
  a = b = c = JHASH_INITVAL + (length << 2) + initval;

  /* Handle most of the key */
  while (length > 3) {
    a += k[0];
    b += k[1];
    c += k[2];
    __jhash_mix(a, b, c);
    length -= 3;
    k += 3;
  }

  return c;
}

/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static __always_inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval)
{
  a += initval;
  b += initval;
  c += initval;

  __jhash_final(a, b, c);

  return c;
}

static __always_inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
  return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static __always_inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
  return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static __always_inline u32 jhash_1word(u32 a, u32 initval)
{
  return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#endif /* _LINUX_JHASH_H */
