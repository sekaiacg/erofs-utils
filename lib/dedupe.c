// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2022 Alibaba Cloud
 */
#include <stdlib.h>
#include "erofs/dedupe.h"
#include "erofs/print.h"
#include "rolling_hash.h"
#include "liberofs_xxhash.h"
#include "sha256.h"

unsigned long erofs_memcmp2(const u8 *s1, const u8 *s2,
			    unsigned long sz)
{
	const unsigned long *a1, *a2;
	unsigned long n = sz;

	if (sz < sizeof(long))
		goto out_bytes;

	if (((long)s1 & (sizeof(long) - 1)) ==
			((long)s2 & (sizeof(long) - 1))) {
		while ((long)s1 & (sizeof(long) - 1)) {
			if (*s1 != *s2)
				break;
			++s1;
			++s2;
			--sz;
		}

		a1 = (const unsigned long *)s1;
		a2 = (const unsigned long *)s2;
		while (sz >= sizeof(long)) {
			if (*a1 != *a2)
				break;
			++a1;
			++a2;
			sz -= sizeof(long);
		}
	} else {
		a1 = (const unsigned long *)s1;
		a2 = (const unsigned long *)s2;
		do {
			if (get_unaligned(a1) != get_unaligned(a2))
				break;
			++a1;
			++a2;
			sz -= sizeof(long);
		} while (sz >= sizeof(long));
	}
	s1 = (const u8 *)a1;
	s2 = (const u8 *)a2;
out_bytes:
	while (sz) {
		if (*s1 != *s2)
			break;
		++s1;
		++s2;
		--sz;
	}
	return n - sz;
}

static unsigned int window_size, rollinghash_rm;
static struct list_head dedupe_tree[65536];
struct z_erofs_dedupe_item *dedupe_subtree;

struct z_erofs_dedupe_item {
	struct list_head list;
	struct z_erofs_dedupe_item *chain;
	long long	hash;
	u8		prefix_sha256[32];
	u64		prefix_xxh64;

	erofs_off_t	pstart;
	unsigned int	plen;

	int		original_length;
	bool		partial, raw;
	u8		extra_data[];
};

int z_erofs_dedupe_match(struct z_erofs_dedupe_ctx *ctx)
{
	struct z_erofs_dedupe_item e_find;
	u8 *cur;
	bool initial = true;

	if (!window_size)
		return -ENOENT;

	if (ctx->cur > ctx->end - window_size)
		cur = ctx->end - window_size;
	else
		cur = ctx->cur;

	/* move backward byte-by-byte */
	for (; cur >= ctx->start; --cur) {
		struct list_head *p;
		struct z_erofs_dedupe_item *e;

		unsigned int extra = 0;
		u64 xxh64_csum = 0;
		u8 sha256[32];

		if (initial) {
			/* initial try */
			e_find.hash = erofs_rolling_hash_init(cur, window_size, true);
			initial = false;
		} else {
			e_find.hash = erofs_rolling_hash_advance(e_find.hash,
				rollinghash_rm, cur[window_size], cur[0]);
		}

		p = &dedupe_tree[e_find.hash & (ARRAY_SIZE(dedupe_tree) - 1)];
		list_for_each_entry(e, p, list) {
			if (e->hash != e_find.hash)
				continue;
			if (!extra) {
				xxh64_csum = xxh64(cur, window_size, 0);
				extra = 1;
			}
			if (e->prefix_xxh64 == xxh64_csum)
				break;
		}

		if (&e->list == p)
			continue;

		erofs_sha256(cur, window_size, sha256);
		if (memcmp(sha256, e->prefix_sha256, sizeof(sha256)))
			continue;

		extra = min_t(unsigned int, ctx->end - cur - window_size,
			      e->original_length - window_size);
		extra = erofs_memcmp2(cur + window_size, e->extra_data, extra);
		if (window_size + extra <= ctx->cur - cur)
			continue;
		ctx->cur = cur;
		ctx->e.length = window_size + extra;
		ctx->e.partial = e->partial ||
			(window_size + extra < e->original_length);
		ctx->e.raw = e->raw;
		ctx->e.inlined = false;
		ctx->e.pstart = e->pstart;
		ctx->e.plen = e->plen;
		return 0;
	}
	return -ENOENT;
}

int z_erofs_dedupe_insert(struct z_erofs_inmem_extent *e,
			  void *original_data)
{
	struct list_head *p;
	struct z_erofs_dedupe_item *di, *k;

	if (!window_size || e->length < window_size)
		return 0;

	di = malloc(sizeof(*di) + e->length - window_size);
	if (!di)
		return -ENOMEM;

	di->prefix_xxh64 = xxh64(original_data, window_size, 0);
	di->hash = erofs_rolling_hash_init(original_data,
			window_size, true);

	/* skip the same xxh64 hash */
	p = &dedupe_tree[di->hash & (ARRAY_SIZE(dedupe_tree) - 1)];
	list_for_each_entry(k, p, list) {
		if (k->prefix_xxh64 == di->prefix_xxh64) {
			free(di);
			return 0;
		}
	}

	di->original_length = e->length;
	erofs_sha256(original_data, window_size, di->prefix_sha256);
	memcpy(di->extra_data, original_data + window_size,
	       e->length - window_size);
	di->pstart = e->pstart;
	di->plen = e->plen;
	di->partial = e->partial;
	di->raw = e->raw;
	di->chain = dedupe_subtree;
	dedupe_subtree = di;
	list_add_tail(&di->list, p);
	return 0;
}

void z_erofs_dedupe_commit(bool drop)
{
	if (!dedupe_subtree)
		return;
	if (drop) {
		struct z_erofs_dedupe_item *di, *n;

		for (di = dedupe_subtree; di; di = n) {
			n = di->chain;
			list_del(&di->list);
			free(di);
		}
	}
	dedupe_subtree = NULL;
}

int z_erofs_dedupe_init(unsigned int wsiz)
{
	struct list_head *p;

	for (p = dedupe_tree;
		p < dedupe_tree + ARRAY_SIZE(dedupe_tree); ++p)
		init_list_head(p);

	window_size = wsiz;
	rollinghash_rm = erofs_rollinghash_calc_rm(window_size);
	return 0;
}

void z_erofs_dedupe_exit(void)
{
	struct z_erofs_dedupe_item *di, *n;
	struct list_head *p;

	if (!window_size)
		return;

	z_erofs_dedupe_commit(true);

	for (p = dedupe_tree;
		p < dedupe_tree + ARRAY_SIZE(dedupe_tree); ++p) {
		list_for_each_entry_safe(di, n, p, list) {
			list_del(&di->list);
			free(di);
		}
	}
	dedupe_subtree = NULL;
}
