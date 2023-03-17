/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 * Modified by Gao Xiang <gaoxiang25@huawei.com>
 */
#ifndef __EROFS_DEFS_H
#define __EROFS_DEFS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LINUX_TYPES_H
#include <linux/types.h>
#endif

/*
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 */
#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) *__mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

typedef uint8_t         u8;
typedef uint16_t        u16;
typedef uint32_t        u32;
typedef uint64_t        u64;

#ifndef HAVE_LINUX_TYPES_H
typedef u8	__u8;
typedef u16	__u16;
typedef u32	__u32;
typedef u64	__u64;
typedef u16	__le16;
typedef u32	__le32;
typedef u64	__le64;
typedef u16	__be16;
typedef u32	__be32;
typedef u64	__be64;
#endif

typedef int8_t          s8;
typedef int16_t         s16;
typedef int32_t         s32;
typedef int64_t         s64;

#if __BYTE_ORDER == __LITTLE_ENDIAN
/*
 * The host byte order is the same as network byte order,
 * so these functions are all just identity.
 */
#define cpu_to_le16(x) ((__u16)(x))
#define cpu_to_le32(x) ((__u32)(x))
#define cpu_to_le64(x) ((__u64)(x))
#define le16_to_cpu(x) ((__u16)(x))
#define le32_to_cpu(x) ((__u32)(x))
#define le64_to_cpu(x) ((__u64)(x))

#else
#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le16(x) (__builtin_bswap16(x))
#define cpu_to_le32(x) (__builtin_bswap32(x))
#define cpu_to_le64(x) (__builtin_bswap64(x))
#define le16_to_cpu(x) (__builtin_bswap16(x))
#define le32_to_cpu(x) (__builtin_bswap32(x))
#define le64_to_cpu(x) (__builtin_bswap64(x))
#else
#pragma error
#endif
#endif

#ifdef __cplusplus
#define BUILD_BUG_ON(condition) static_assert(!(condition))
#elif !defined(__OPTIMIZE__)
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2 * !!(condition)]))
#else
#define BUILD_BUG_ON(condition) assert(!(condition))
#endif

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define __round_mask(x, y)      ((__typeof__(x))((y)-1))
#define round_up(x, y)          ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y)        ((x) & ~__round_mask(x, y))

#ifndef roundup
/* The `const' in roundup() prevents gcc-3.3 from calling __divdi3 */
#define roundup(x, y) (					\
{							\
	const typeof(y) __y = y;			\
	(((x) + (__y - 1)) / __y) * __y;		\
}							\
)
#endif
#define rounddown(x, y) (				\
{							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
}							\
)

/* Can easily conflict with C++'s std::min */
#ifndef __cplusplus
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })
#endif

/*
 * ..and if you can't take the strict types, you can specify one yourself.
 * Or don't use min/max at all, of course.
 */
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })

#define cmpsgn(x, y) ({		\
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(_x > _y) - (_x < _y); })

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define BIT(nr)             (1UL << (nr))
#define BIT_ULL(nr)         (1ULL << (nr))
#define BIT_MASK(nr)        (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)        ((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)    (1ULL << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)    ((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE       8
#define BITS_TO_LONGS(nr)   DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#ifdef __SIZEOF_LONG__
#define BITS_PER_LONG (__CHAR_BIT__ * __SIZEOF_LONG__)
#else
#define BITS_PER_LONG __WORDSIZE
#endif

#define BUG_ON(cond)        assert(!(cond))

#ifdef NDEBUG
#define DBG_BUGON(condition)	((void)(condition))
#else
#define DBG_BUGON(condition)	BUG_ON(condition)
#endif

#ifndef __maybe_unused
#define __maybe_unused      __attribute__((__unused__))
#endif

#define __packed __attribute__((__packed__))

#define __get_unaligned_t(type, ptr) ({						\
	const struct { type x; } __packed *__pptr = (typeof(__pptr))(ptr);	\
	__pptr->x;								\
})

#define __put_unaligned_t(type, val, ptr) do {					\
	struct { type x; } __packed *__pptr = (typeof(__pptr))(ptr);		\
	__pptr->x = (val);							\
} while (0)

#define get_unaligned(ptr)	__get_unaligned_t(typeof(*(ptr)), (ptr))
#define put_unaligned(val, ptr) __put_unaligned_t(typeof(*(ptr)), (val), (ptr))

static inline u32 get_unaligned_le32(const void *p)
{
	return le32_to_cpu(__get_unaligned_t(__le32, p));
}

static inline void put_unaligned_le32(u32 val, void *p)
{
	__put_unaligned_t(__le32, cpu_to_le32(val), p);
}

/**
 * ilog2 - log of base 2 of 32-bit or a 64-bit unsigned value
 * @n - parameter
 *
 * constant-capable log of base 2 calculation
 * - this can be used to initialise global variables from constant data, hence
 *   the massive ternary operator construction
 *
 * selects the appropriately-sized optimised version depending on sizeof(n)
 */
#define ilog2(n)			\
(					\
	(n) & (1ULL << 63) ? 63 :	\
	(n) & (1ULL << 62) ? 62 :	\
	(n) & (1ULL << 61) ? 61 :	\
	(n) & (1ULL << 60) ? 60 :	\
	(n) & (1ULL << 59) ? 59 :	\
	(n) & (1ULL << 58) ? 58 :	\
	(n) & (1ULL << 57) ? 57 :	\
	(n) & (1ULL << 56) ? 56 :	\
	(n) & (1ULL << 55) ? 55 :	\
	(n) & (1ULL << 54) ? 54 :	\
	(n) & (1ULL << 53) ? 53 :	\
	(n) & (1ULL << 52) ? 52 :	\
	(n) & (1ULL << 51) ? 51 :	\
	(n) & (1ULL << 50) ? 50 :	\
	(n) & (1ULL << 49) ? 49 :	\
	(n) & (1ULL << 48) ? 48 :	\
	(n) & (1ULL << 47) ? 47 :	\
	(n) & (1ULL << 46) ? 46 :	\
	(n) & (1ULL << 45) ? 45 :	\
	(n) & (1ULL << 44) ? 44 :	\
	(n) & (1ULL << 43) ? 43 :	\
	(n) & (1ULL << 42) ? 42 :	\
	(n) & (1ULL << 41) ? 41 :	\
	(n) & (1ULL << 40) ? 40 :	\
	(n) & (1ULL << 39) ? 39 :	\
	(n) & (1ULL << 38) ? 38 :	\
	(n) & (1ULL << 37) ? 37 :	\
	(n) & (1ULL << 36) ? 36 :	\
	(n) & (1ULL << 35) ? 35 :	\
	(n) & (1ULL << 34) ? 34 :	\
	(n) & (1ULL << 33) ? 33 :	\
	(n) & (1ULL << 32) ? 32 :	\
	(n) & (1ULL << 31) ? 31 :	\
	(n) & (1ULL << 30) ? 30 :	\
	(n) & (1ULL << 29) ? 29 :	\
	(n) & (1ULL << 28) ? 28 :	\
	(n) & (1ULL << 27) ? 27 :	\
	(n) & (1ULL << 26) ? 26 :	\
	(n) & (1ULL << 25) ? 25 :	\
	(n) & (1ULL << 24) ? 24 :	\
	(n) & (1ULL << 23) ? 23 :	\
	(n) & (1ULL << 22) ? 22 :	\
	(n) & (1ULL << 21) ? 21 :	\
	(n) & (1ULL << 20) ? 20 :	\
	(n) & (1ULL << 19) ? 19 :	\
	(n) & (1ULL << 18) ? 18 :	\
	(n) & (1ULL << 17) ? 17 :	\
	(n) & (1ULL << 16) ? 16 :	\
	(n) & (1ULL << 15) ? 15 :	\
	(n) & (1ULL << 14) ? 14 :	\
	(n) & (1ULL << 13) ? 13 :	\
	(n) & (1ULL << 12) ? 12 :	\
	(n) & (1ULL << 11) ? 11 :	\
	(n) & (1ULL << 10) ? 10 :	\
	(n) & (1ULL <<  9) ?  9 :	\
	(n) & (1ULL <<  8) ?  8 :	\
	(n) & (1ULL <<  7) ?  7 :	\
	(n) & (1ULL <<  6) ?  6 :	\
	(n) & (1ULL <<  5) ?  5 :	\
	(n) & (1ULL <<  4) ?  4 :	\
	(n) & (1ULL <<  3) ?  3 :	\
	(n) & (1ULL <<  2) ?  2 :	\
	(n) & (1ULL <<  1) ?  1 : 0	\
)

static inline unsigned int fls_long(unsigned long x)
{
	return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
}

/**
 * __roundup_pow_of_two() - round up to nearest power of two
 * @n: value to round up
 */
static inline __attribute__((const))
unsigned long __roundup_pow_of_two(unsigned long n)
{
	return 1UL << fls_long(n - 1);
}

/**
 * roundup_pow_of_two - round the given value up to nearest power of two
 * @n: parameter
 *
 * round the given value up to the nearest power of two
 * - the result is undefined when n == 0
 * - this can be used to initialise global variables from constant data
 */
#define roundup_pow_of_two(n)			\
(						\
	__builtin_constant_p(n) ? (		\
		((n) == 1) ? 1 :		\
		(1UL << (ilog2((n) - 1) + 1))	\
				   ) :		\
	__roundup_pow_of_two(n)			\
)

#ifndef __always_inline
#define __always_inline	inline
#endif

#ifdef HAVE_STRUCT_STAT_ST_ATIM
/* Linux */
#define ST_ATIM_NSEC(stbuf) ((stbuf)->st_atim.tv_nsec)
#define ST_CTIM_NSEC(stbuf) ((stbuf)->st_ctim.tv_nsec)
#define ST_MTIM_NSEC(stbuf) ((stbuf)->st_mtim.tv_nsec)
#elif defined(HAVE_STRUCT_STAT_ST_ATIMENSEC)
/* macOS */
#define ST_ATIM_NSEC(stbuf) ((stbuf)->st_atimensec)
#define ST_CTIM_NSEC(stbuf) ((stbuf)->st_ctimensec)
#define ST_MTIM_NSEC(stbuf) ((stbuf)->st_mtimensec)
#else
#define ST_ATIM_NSEC(stbuf) 0
#define ST_CTIM_NSEC(stbuf) 0
#define ST_MTIM_NSEC(stbuf) 0
#endif

#ifdef __cplusplus
}
#endif

#endif
