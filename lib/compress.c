// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Miao Xie <miaoxie@huawei.com>
 * with heavy changes by Gao Xiang <xiang@kernel.org>
 */
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#ifdef EROFS_MT_ENABLED
#include <pthread.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "erofs/print.h"
#include "erofs/compress.h"
#include "erofs/dedupe.h"
#include "compressor.h"
#include "erofs/block_list.h"
#include "erofs/compress_hints.h"
#include "erofs/fragments.h"
#ifdef EROFS_MT_ENABLED
#include "erofs/workqueue.h"
#endif
#include "liberofs_cache.h"
#include "liberofs_metabox.h"

#define Z_EROFS_DESTBUF_SZ	(Z_EROFS_PCLUSTER_MAX_SIZE + EROFS_MAX_BLOCK_SIZE * 2)

struct z_erofs_extent_item {
	struct list_head list;
	struct z_erofs_inmem_extent e;
};

struct z_erofs_compress_ictx {		/* inode context */
	struct erofs_inode *inode;
	struct erofs_compress_cfg *ccfg;
	int fd;
	u64 fpos;

	u32 tofh;
	bool fix_dedupedfrag;
	bool fragemitted;
	bool dedupe;
	bool data_unaligned;

	/* fields for write indexes */
	u8 *metacur;
	struct list_head extents;
	u16 clusterofs;
	int seg_num;

#if EROFS_MT_ENABLED
	pthread_mutex_t mutex;
	pthread_cond_t cond;

	struct erofs_compress_work *mtworks;
#endif
};

struct z_erofs_compress_sctx {		/* segment context */
	union {
		struct list_head extents;
		struct list_head sibling;
	};
	struct z_erofs_compress_ictx *ictx;

	u8 *queue;
	struct z_erofs_extent_item *pivot;

	struct erofs_compress *chandle;
	char *destbuf;

	erofs_off_t remaining;
	unsigned int head, tail;

	unsigned int pclustersize;
	erofs_off_t pstart, poff;
	u16 clusterofs;

	int seg_idx;

	void *membuf;
};

#ifdef EROFS_MT_ENABLED
struct erofs_compress_wq_tls {
	u8 *queue;
	char *destbuf;
	struct erofs_compress_cfg *ccfg;
};

struct erofs_compress_work {
	/* Note: struct erofs_work must be the first member */
	struct erofs_work work;
	struct z_erofs_compress_sctx ctx;
	pthread_cond_t cond;
	struct erofs_compress_work *next;

	unsigned int alg_id;
	char *alg_name;
	unsigned int comp_level;
	unsigned int dict_size;

	int errcode;
};

static struct {
	struct erofs_workqueue wq;
	struct erofs_compress_work *idle;
	pthread_mutex_t mutex;
	bool hasfwq;
} z_erofs_mt_ctrl;

struct z_erofs_compress_fslot {
	struct list_head pending;
	pthread_mutex_t lock;
	bool inprogress;
};

#endif

/* compressing configuration specified by users */
struct erofs_compress_cfg {
	struct erofs_compress handle;
	unsigned int algorithmtype;
	bool enable;
};

struct z_erofs_mgr {
	struct erofs_compress_cfg ccfg[EROFS_MAX_COMPR_CFGS];
#ifdef EROFS_MT_ENABLED
	struct z_erofs_compress_fslot fslot[1024];
#endif
};

static bool z_erofs_mt_enabled;

#define Z_EROFS_LEGACY_MAP_HEADER_SIZE	Z_EROFS_FULL_INDEX_START(0)

static void z_erofs_fini_full_indexes(struct z_erofs_compress_ictx *ctx)
{
	const unsigned int type = Z_EROFS_LCLUSTER_TYPE_PLAIN;
	struct z_erofs_lcluster_index di;

	if (!ctx->clusterofs)
		return;

	di.di_clusterofs = cpu_to_le16(ctx->clusterofs);
	di.di_u.blkaddr = 0;
	di.di_advise = cpu_to_le16(type);

	memcpy(ctx->metacur, &di, sizeof(di));
	ctx->metacur += sizeof(di);
}

static void z_erofs_write_full_indexes(struct z_erofs_compress_ictx *ctx,
				       struct z_erofs_inmem_extent *e)
{
	struct erofs_inode *inode = ctx->inode;
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int clusterofs = ctx->clusterofs;
	unsigned int count = e->length;
	unsigned int bbits = sbi->blkszbits;
	unsigned int d0 = 0, d1 = (clusterofs + count) >> bbits;
	struct z_erofs_lcluster_index di;
	unsigned int type, advise;

	DBG_BUGON(!count);
	DBG_BUGON(e->pstart & (BIT(bbits) - 1));

	di.di_clusterofs = cpu_to_le16(ctx->clusterofs);

	/* whether the tail-end (un)compressed block or not */
	if (!d1) {
		/*
		 * A lcluster cannot have three parts with the middle one which
		 * is well-compressed for !ztailpacking cases.
		 */
		DBG_BUGON(!e->raw && !cfg.c_ztailpacking && !cfg.c_fragments);
		DBG_BUGON(e->partial);
		type = e->raw ? Z_EROFS_LCLUSTER_TYPE_PLAIN :
			Z_EROFS_LCLUSTER_TYPE_HEAD1;
		di.di_advise = cpu_to_le16(type);

		if (inode->datalayout == EROFS_INODE_COMPRESSED_FULL && !e->plen)
			di.di_u.blkaddr = cpu_to_le32(inode->fragmentoff >> 32);
		else
			di.di_u.blkaddr = cpu_to_le32(e->pstart >> bbits);
		memcpy(ctx->metacur, &di, sizeof(di));
		ctx->metacur += sizeof(di);

		/* don't add the final index if the tail-end block exists */
		ctx->clusterofs = 0;
		return;
	}

	do {
		advise = 0;
		/* XXX: big pcluster feature should be per-inode */
		if (d0 == 1 && erofs_sb_has_big_pcluster(sbi)) {
			type = Z_EROFS_LCLUSTER_TYPE_NONHEAD;
			di.di_u.delta[0] = cpu_to_le16((e->plen >> bbits) |
						       Z_EROFS_LI_D0_CBLKCNT);
			di.di_u.delta[1] = cpu_to_le16(d1);
		} else if (d0) {
			type = Z_EROFS_LCLUSTER_TYPE_NONHEAD;

			/*
			 * If the |Z_EROFS_VLE_DI_D0_CBLKCNT| bit is set, parser
			 * will interpret |delta[0]| as size of pcluster, rather
			 * than distance to last head cluster. Normally this
			 * isn't a problem, because uncompressed extent size are
			 * below Z_EROFS_VLE_DI_D0_CBLKCNT * BLOCK_SIZE = 8MB.
			 * But with large pcluster it's possible to go over this
			 * number, resulting in corrupted compressed indices.
			 * To solve this, we replace d0 with
			 * Z_EROFS_VLE_DI_D0_CBLKCNT-1.
			 */
			if (d0 >= Z_EROFS_LI_D0_CBLKCNT)
				di.di_u.delta[0] = cpu_to_le16(
						Z_EROFS_LI_D0_CBLKCNT - 1);
			else
				di.di_u.delta[0] = cpu_to_le16(d0);
			di.di_u.delta[1] = cpu_to_le16(d1);
		} else {
			type = e->raw ? Z_EROFS_LCLUSTER_TYPE_PLAIN :
				Z_EROFS_LCLUSTER_TYPE_HEAD1;

			if (inode->datalayout == EROFS_INODE_COMPRESSED_FULL &&
			    !e->plen)
				di.di_u.blkaddr = cpu_to_le32(inode->fragmentoff >> 32);
			else
				di.di_u.blkaddr = cpu_to_le32(e->pstart >> bbits);

			if (e->partial) {
				DBG_BUGON(e->raw);
				advise |= Z_EROFS_LI_PARTIAL_REF;
			}
		}
		di.di_advise = cpu_to_le16(advise | type);

		memcpy(ctx->metacur, &di, sizeof(di));
		ctx->metacur += sizeof(di);

		count -= (1 << bbits) - clusterofs;
		clusterofs = 0;

		++d0;
		--d1;
	} while (clusterofs + count >= 1 << bbits);

	ctx->clusterofs = clusterofs + count;
}

static bool z_erofs_need_refill(struct z_erofs_compress_sctx *ctx)
{
	const bool final = !ctx->remaining;
	unsigned int qh_aligned, qh_after;
	struct erofs_inode *inode = ctx->ictx->inode;

	if (final || ctx->head < EROFS_CONFIG_COMPR_MAX_SZ)
		return false;

	qh_aligned = round_down(ctx->head, erofs_blksiz(inode->sbi));
	qh_after = ctx->head - qh_aligned;
	memmove(ctx->queue, ctx->queue + qh_aligned, ctx->tail - qh_aligned);
	ctx->tail -= qh_aligned;
	ctx->head = qh_after;
	return true;
}

static struct z_erofs_extent_item dummy_pivot = {
	.e.length = 0
};

static void z_erofs_commit_extent(struct z_erofs_compress_sctx *ctx,
				  struct z_erofs_extent_item *ei)
{
	if (ei == &dummy_pivot)
		return;

	list_add_tail(&ei->list, &ctx->extents);
	ctx->clusterofs = (ctx->clusterofs + ei->e.length) &
			  (erofs_blksiz(ctx->ictx->inode->sbi) - 1);
}

static int z_erofs_compress_dedupe(struct z_erofs_compress_sctx *ctx)
{
	struct erofs_inode *inode = ctx->ictx->inode;
	const unsigned int lclustermask = (1 << inode->z_lclusterbits) - 1;
	struct erofs_sb_info *sbi = inode->sbi;
	struct z_erofs_extent_item *ei = ctx->pivot;

	if (!ei)
		return 0;

	/*
	 * No need dedupe for packed inode since it is composed of
	 * fragments which have already been deduplicated.
	 */
	if (erofs_is_packed_inode(inode))
		goto out;

	do {
		struct z_erofs_dedupe_ctx dctx = {
			.start = ctx->queue + ctx->head - ({ int rc;
				if (ei->e.length <= erofs_blksiz(sbi))
					rc = 0;
				else if (ei->e.length - erofs_blksiz(sbi) >= ctx->head)
					rc = ctx->head;
				else
					rc = ei->e.length - erofs_blksiz(sbi);
				rc; }),
			.end = ctx->queue + ctx->tail,
			.cur = ctx->queue + ctx->head,
		};
		int delta;

		if (z_erofs_dedupe_match(&dctx))
			break;

		DBG_BUGON(dctx.e.inlined);
		delta = ctx->queue + ctx->head - dctx.cur;
		/*
		 * For big pcluster dedupe, leave two indices at least to store
		 * CBLKCNT as the first step.  Even laterly, an one-block
		 * decompresssion could be done as another try in practice.
		 */
		if (dctx.e.plen > erofs_blksiz(sbi) &&
		    ((ctx->clusterofs + ei->e.length - delta) & lclustermask) +
			dctx.e.length < 2 * (lclustermask + 1))
			break;

		ctx->pivot = malloc(sizeof(struct z_erofs_extent_item));
		if (!ctx->pivot) {
			z_erofs_commit_extent(ctx, ei);
			return -ENOMEM;
		}

		if (delta) {
			DBG_BUGON(delta < 0);
			DBG_BUGON(!ei->e.length);

			/*
			 * For big pcluster dedupe, if we decide to shorten the
			 * previous big pcluster, make sure that the previous
			 * CBLKCNT is still kept.
			 */
			if (ei->e.plen > erofs_blksiz(sbi) &&
			    (ctx->clusterofs & lclustermask) + ei->e.length
				- delta < 2 * (lclustermask + 1))
				break;
			ei->e.partial = true;
			ei->e.length -= delta;
		}
		ctx->ictx->dedupe = true;
		erofs_sb_set_dedupe(sbi);

		sbi->saved_by_deduplication += dctx.e.plen;
		erofs_dbg("Dedupe %u %scompressed data (delta %d) to %llu of %u bytes",
			  dctx.e.length, dctx.e.raw ? "un" : "",
			  delta, dctx.e.pstart | 0ULL, dctx.e.plen);

		z_erofs_commit_extent(ctx, ei);
		ei = ctx->pivot;
		init_list_head(&ei->list);
		ei->e = dctx.e;

		ctx->head += dctx.e.length - delta;
		DBG_BUGON(ctx->head > ctx->tail);

		if (z_erofs_need_refill(ctx))
			return 1;
	} while (ctx->tail > ctx->head);
out:
	z_erofs_commit_extent(ctx, ei);
	ctx->pivot = NULL;
	return 0;
}

/* TODO: reset clusterofs to 0 if permitted */
static int write_uncompressed_block(struct z_erofs_compress_sctx *ctx,
				    unsigned int len, char *dst)
{
	struct erofs_inode *inode = ctx->ictx->inode;
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int count = min(erofs_blksiz(sbi), len);
	unsigned int interlaced_offset, rightpart;
	int ret;

	/* write interlaced uncompressed data if needed */
	if (inode->z_advise & Z_EROFS_ADVISE_INTERLACED_PCLUSTER)
		interlaced_offset = ctx->clusterofs;
	else
		interlaced_offset = 0;
	rightpart = min(erofs_blksiz(sbi) - interlaced_offset, count);

	memset(dst, 0, erofs_blksiz(sbi));

	memcpy(dst + interlaced_offset, ctx->queue + ctx->head, rightpart);
	memcpy(dst, ctx->queue + ctx->head + rightpart, count - rightpart);

	if (ctx->membuf) {
		erofs_dbg("Recording %u uncompressed data of %s", count,
			  inode->i_srcpath);
		memcpy(ctx->membuf + ctx->poff, dst, erofs_blksiz(sbi));
	} else {
		erofs_dbg("Writing %u uncompressed data to %llu", count,
			  ctx->pstart | 0ULL);
		ret = erofs_dev_write(sbi, dst, ctx->pstart, erofs_blksiz(sbi));
		if (ret)
			return ret;
	}
	ctx->poff += erofs_blksiz(sbi);
	return count;
}

static int write_uncompressed_extents(struct z_erofs_compress_sctx *ctx,
				      unsigned int size, unsigned int processed,
				      char *dst)
{
	struct erofs_inode *inode = ctx->ictx->inode;
	unsigned int lclustersize = 1 << inode->z_lclusterbits;
	struct z_erofs_extent_item *ei;
	int count;

	while (1) {
		count = write_uncompressed_block(ctx, size, dst);
		if (count < 0)
			return count;

		size -= count;
		if (processed < lclustersize + count)
			break;
		processed -= count;

		ei = malloc(sizeof(*ei));
		if (!ei)
			return -ENOMEM;
		init_list_head(&ei->list);

		ei->e = (struct z_erofs_inmem_extent) {
			.length = count,
			.plen = round_up(count, erofs_blksiz(inode->sbi)),
			.raw = true,
			.pstart = ctx->pstart,
		};
		if (ctx->pstart != EROFS_NULL_ADDR)
			ctx->pstart += ei->e.plen;
		z_erofs_commit_extent(ctx, ei);
		ctx->head += count;
	}
	return count;
}

static unsigned int z_erofs_get_max_pclustersize(struct erofs_inode *inode)
{
	if (erofs_is_packed_inode(inode)) {
		return cfg.c_mkfs_pclustersize_packed;
	} else if (erofs_is_metabox_inode(inode)) {
		return cfg.c_mkfs_pclustersize_metabox;
#ifndef NDEBUG
	} else if (cfg.c_random_pclusterblks) {
		unsigned int pclusterblks =
			cfg.c_mkfs_pclustersize_max >> inode->sbi->blkszbits;

		return (1 + rand() % pclusterblks) << inode->sbi->blkszbits;
#endif
	} else if (cfg.c_compress_hints_file) {
		z_erofs_apply_compress_hints(inode);
		DBG_BUGON(!inode->z_physical_clusterblks);
		return inode->z_physical_clusterblks << inode->sbi->blkszbits;
	}
	return cfg.c_mkfs_pclustersize_def;
}

static int z_erofs_fill_inline_data(struct erofs_inode *inode, void *data,
				    unsigned int len, bool raw)
{
	inode->z_advise |= Z_EROFS_ADVISE_INLINE_PCLUSTER;
	inode->idata_size = len;
	inode->compressed_idata = !raw;

	inode->idata = malloc(inode->idata_size);
	if (!inode->idata)
		return -ENOMEM;
	erofs_dbg("Recording %u %scompressed inline data",
		  inode->idata_size, raw ? "un" : "");
	memcpy(inode->idata, data, inode->idata_size);
	return len;
}

static int tryrecompress_trailing(struct z_erofs_compress_sctx *ctx,
				  struct erofs_compress *ec,
				  void *in, unsigned int *insize,
				  void *out, unsigned int *compressedsize)
{
	struct erofs_sb_info *sbi = ctx->ictx->inode->sbi;
	char *tmp;
	unsigned int count;
	int ret = *compressedsize;

	/* no need to recompress */
	if (!(ret & (erofs_blksiz(sbi) - 1)))
		return 0;

	tmp = malloc(Z_EROFS_PCLUSTER_MAX_SIZE);
	if (!tmp)
		return -ENOMEM;

	count = *insize;
	ret = erofs_compress_destsize(ec, in, &count, (void *)tmp,
				      rounddown(ret, erofs_blksiz(sbi)));
	if (ret <= 0 || ret + (*insize - count) >=
			roundup(*compressedsize, erofs_blksiz(sbi)))
		goto out;

	/* replace the original compressed data if any gain */
	memcpy(out, tmp, ret);
	*insize = count;
	*compressedsize = ret;

out:
	free(tmp);
	return 0;
}

static bool z_erofs_fixup_deduped_fragment(struct z_erofs_compress_sctx *ctx)
{
	struct z_erofs_compress_ictx *ictx = ctx->ictx;
	struct erofs_inode *inode = ictx->inode;
	struct erofs_sb_info *sbi = inode->sbi;
	const unsigned int newsize = ctx->remaining + ctx->tail - ctx->head;

	DBG_BUGON(!inode->fragment_size);

	/* try to fix again if it gets larger (should be rare) */
	if (inode->fragment_size < newsize) {
		ctx->pclustersize = min_t(erofs_off_t,
				z_erofs_get_max_pclustersize(inode),
				roundup(newsize - inode->fragment_size,
					erofs_blksiz(sbi)));
		return false;
	}

	inode->fragment_size = newsize;
	erofs_dbg("Reducing fragment size to %llu", inode->fragment_size | 0ULL);

	/* it's the end */
	DBG_BUGON(ctx->tail - ctx->head + ctx->remaining != newsize);
	ctx->head = ctx->tail;
	ctx->remaining = 0;
	return true;
}

static int __z_erofs_compress_one(struct z_erofs_compress_sctx *ctx,
				  struct z_erofs_inmem_extent *e)
{
	static char g_dstbuf[Z_EROFS_DESTBUF_SZ];
	char *dstbuf = ctx->destbuf ?: g_dstbuf;
	struct z_erofs_compress_ictx *ictx = ctx->ictx;
	struct erofs_inode *inode = ictx->inode;
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int blksz = erofs_blksiz(sbi);
	char *const dst = dstbuf + blksz;
	struct erofs_compress *const h = ctx->chandle;
	unsigned int len = ctx->tail - ctx->head;
	bool is_packed_inode = erofs_is_packed_inode(inode);
	bool tsg = (ctx->seg_idx + 1 >= ictx->seg_num), final = !ctx->remaining;
	bool may_packing = (cfg.c_fragments && tsg && final && !is_packed_inode &&
			    !erofs_is_metabox_inode(inode));
	bool data_unaligned = ictx->data_unaligned;
	bool may_inline = (cfg.c_ztailpacking && !data_unaligned && tsg &&
			   final && !may_packing);
	unsigned int compressedsize;
	int ret;

	DBG_BUGON(ctx->pivot);
	*e = (struct z_erofs_inmem_extent){};
	if (len <= ctx->pclustersize) {
		if (!final || !len)
			return 1;
		if (may_packing && inode->fragment_size && !ictx->fix_dedupedfrag) {
			ctx->pclustersize = roundup(len, blksz);
			goto fix_dedupedfrag;
		}
		e->length = len;
		if (may_packing)
			goto frag_packing;
		if (!may_inline && len <= blksz)
			goto nocompression;
	}

	e->length = min(len, cfg.c_max_decompressed_extent_bytes);
	if (data_unaligned) {
		ret = erofs_compress(h, ctx->queue + ctx->head, e->length,
				     dst, ctx->pclustersize);
		if (ret == -EOPNOTSUPP) {
			data_unaligned = false;
			goto retry_aligned;
		}
	} else {
retry_aligned:
		ret = erofs_compress_destsize(h, ctx->queue + ctx->head,
					      &e->length, dst, ctx->pclustersize);
	}

	if (ret > 0) {
		compressedsize = ret;
		/* even compressed size is smaller, there is no real gain */
		if (!data_unaligned && !(may_inline && e->length == len && ret < blksz))
			ret = roundup(ret, blksz);
	} else if (ret != -ENOSPC) {
		erofs_err("failed to compress %s: %s", inode->i_srcpath,
			  erofs_strerror(ret));
		return ret;
	}

	/* check if there is enough gain to keep the compressed data */
	if (ret < 0 || ret * h->compress_threshold / 100 >= e->length) {
		if (may_inline && len < blksz) {
			ret = z_erofs_fill_inline_data(inode,
					ctx->queue + ctx->head, len, true);
			if (ret < 0)
				return ret;
			e->inlined = true;
		} else {
			may_inline = false;
			may_packing = false;
			e->length = min_t(u32, e->length, ctx->pclustersize);
nocompression:
			if (cfg.c_dedupe)
				ret = write_uncompressed_block(ctx, len, dst);
			else
				ret = write_uncompressed_extents(ctx, len,
							e->length, dst);
			if (ret < 0)
				return ret;
		}
		e->length = ret;

		/*
		 * XXX: For now, we have to leave `ctx->compressedblk = 1'
		 * since there is no way to generate compressed indexes after
		 * the time that ztailpacking is decided.
		 */
		e->plen = blksz;
		e->raw = true;
	} else if (may_packing && len == e->length &&
		   compressedsize < ctx->pclustersize &&
		   (!inode->fragment_size || ictx->fix_dedupedfrag)) {
frag_packing:
		ret = erofs_fragment_pack(inode, ctx->queue + ctx->head,
					  ~0ULL, len, ictx->tofh, false);
		if (ret < 0)
			return ret;
		e->plen = 0;	/* indicate a fragment */
		e->raw = false;
		ictx->fragemitted = true;
	/* tailpcluster should be less than 1 block */
	} else if (may_inline && len == e->length && compressedsize < blksz) {
		if (ctx->clusterofs + len <= blksz) {
			inode->eof_tailraw = malloc(len);
			if (!inode->eof_tailraw)
				return -ENOMEM;

			memcpy(inode->eof_tailraw, ctx->queue + ctx->head, len);
			inode->eof_tailrawsize = len;
		}

		ret = z_erofs_fill_inline_data(inode, dst,
				compressedsize, false);
		if (ret < 0)
			return ret;
		e->inlined = true;
		e->plen = blksz;
		e->raw = false;
	} else {
		unsigned int padding;

		/*
		 * If there's space left for the last round when deduping
		 * fragments, try to read the fragment and recompress a little
		 * more to check whether it can be filled up.  Fix the fragment
		 * if succeeds.  Otherwise, just drop it and go on packing.
		 */
		if (!data_unaligned && may_packing && len == e->length &&
		    (compressedsize & (blksz - 1)) &&
		    ctx->tail < Z_EROFS_COMPR_QUEUE_SZ) {
			ctx->pclustersize = roundup(compressedsize, blksz);
			goto fix_dedupedfrag;
		}

		if (may_inline && len == e->length) {
			ret = tryrecompress_trailing(ctx, h,
						     ctx->queue + ctx->head,
						     &e->length, dst,
						     &compressedsize);
			if (ret)
				return ret;
		}

		if (data_unaligned)
			e->plen = compressedsize;
		else
			e->plen = round_up(compressedsize, blksz);
		DBG_BUGON(e->plen >= e->length);
		padding = e->plen - compressedsize;

		/* zero out garbage trailing data for non-0padding */
		if (!erofs_sb_has_lz4_0padding(sbi)) {
			memset(dst + compressedsize, 0, padding);
			padding = 0;
		}

		/* write compressed data */
		if (ctx->membuf) {
			erofs_dbg("Recording %u compressed data of %u bytes of %s",
				  e->length, e->plen, inode->i_srcpath);

			memcpy(ctx->membuf + ctx->poff, dst - padding, e->plen);
		} else {
			erofs_dbg("Writing %u compressed data to %llu of %u bytes",
				  e->length, ctx->pstart, e->plen);

			ret = erofs_dev_write(sbi, dst - padding, ctx->pstart,
					      e->plen);
			if (ret)
				return ret;
		}
		ctx->poff += e->plen;
		e->raw = false;
		may_inline = false;
		may_packing = false;
	}
	e->partial = false;
	e->pstart = ctx->pstart;
	if (ctx->pstart != EROFS_NULL_ADDR)
		ctx->pstart += e->plen;
	if (!may_inline && !may_packing && !is_packed_inode)
		(void)z_erofs_dedupe_insert(e, ctx->queue + ctx->head);
	ctx->head += e->length;
	return 0;

fix_dedupedfrag:
	DBG_BUGON(!inode->fragment_size);
	ctx->remaining += inode->fragment_size;
	ictx->fix_dedupedfrag = true;
	return 1;
}

static int z_erofs_compress_one(struct z_erofs_compress_sctx *ctx)
{
	struct z_erofs_compress_ictx *ictx = ctx->ictx;
	bool tsg = ctx->seg_idx + 1 >= ictx->seg_num;
	struct z_erofs_extent_item *ei;

	while (ctx->tail > ctx->head) {
		int ret = z_erofs_compress_dedupe(ctx);

		if (ret < 0)
			return ret;
		if (ret > 0)
			break;

		ei = malloc(sizeof(*ei));
		if (!ei)
			return -ENOMEM;
		init_list_head(&ei->list);

		ret = __z_erofs_compress_one(ctx, &ei->e);
		if (ret) {
			free(ei);
			if (ret > 0)
				break;		/* need more data */
			return ret;
		}

		ctx->pivot = ei;
		if (tsg && ictx->fix_dedupedfrag && !ictx->fragemitted &&
		    z_erofs_fixup_deduped_fragment(ctx))
			break;

		if (z_erofs_need_refill(ctx))
			break;
	}
	return 0;
}

struct z_erofs_compressindex_vec {
	union {
		erofs_blk_t blkaddr;
		u16 delta[2];
	} u;
	u16 clusterofs;
	u8  clustertype;
};

static void *parse_legacy_indexes(struct z_erofs_compressindex_vec *cv,
				  unsigned int nr, void *metacur)
{
	struct z_erofs_lcluster_index *const db = metacur;
	unsigned int i;

	for (i = 0; i < nr; ++i, ++cv) {
		struct z_erofs_lcluster_index *const di = db + i;
		const unsigned int advise = le16_to_cpu(di->di_advise);

		cv->clustertype = advise & Z_EROFS_LI_LCLUSTER_TYPE_MASK;
		cv->clusterofs = le16_to_cpu(di->di_clusterofs);

		if (cv->clustertype == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
			cv->u.delta[0] = le16_to_cpu(di->di_u.delta[0]);
			cv->u.delta[1] = le16_to_cpu(di->di_u.delta[1]);
		} else {
			cv->u.blkaddr = le32_to_cpu(di->di_u.blkaddr);
		}
	}
	return db + nr;
}

static void *write_compacted_indexes(u8 *out,
				     struct z_erofs_compressindex_vec *cv,
				     erofs_blk_t *blkaddr_ret,
				     unsigned int destsize,
				     unsigned int lclusterbits,
				     bool final, bool *dummy_head,
				     bool update_blkaddr)
{
	unsigned int vcnt, lobits, encodebits, pos, i, cblks;
	erofs_blk_t blkaddr;

	if (destsize == 4)
		vcnt = 2;
	else if (destsize == 2 && lclusterbits <= 12)
		vcnt = 16;
	else
		return ERR_PTR(-EINVAL);
	lobits = max(lclusterbits, ilog2(Z_EROFS_LI_D0_CBLKCNT) + 1U);
	encodebits = (vcnt * destsize * 8 - 32) / vcnt;
	blkaddr = *blkaddr_ret;

	pos = 0;
	for (i = 0; i < vcnt; ++i) {
		unsigned int offset, v;
		u8 ch, rem;

		if (cv[i].clustertype == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
			if (cv[i].u.delta[0] & Z_EROFS_LI_D0_CBLKCNT) {
				cblks = cv[i].u.delta[0] & ~Z_EROFS_LI_D0_CBLKCNT;
				offset = cv[i].u.delta[0];
				blkaddr += cblks;
				*dummy_head = false;
			} else if (i + 1 == vcnt) {
				offset = min_t(u16, cv[i].u.delta[1],
					       Z_EROFS_LI_D0_CBLKCNT - 1);
			} else {
				offset = cv[i].u.delta[0];
			}
		} else {
			offset = cv[i].clusterofs;
			if (*dummy_head) {
				++blkaddr;
				if (update_blkaddr)
					*blkaddr_ret = blkaddr;
			}
			*dummy_head = true;
			update_blkaddr = false;

			if (cv[i].u.blkaddr != blkaddr) {
				if (i + 1 != vcnt)
					DBG_BUGON(!final);
				DBG_BUGON(cv[i].u.blkaddr);
			}
		}
		v = (cv[i].clustertype << lobits) | offset;
		rem = pos & 7;
		ch = out[pos / 8] & ((1 << rem) - 1);
		out[pos / 8] = (v << rem) | ch;
		out[pos / 8 + 1] = v >> (8 - rem);
		out[pos / 8 + 2] = v >> (16 - rem);
		pos += encodebits;
	}
	DBG_BUGON(destsize * vcnt * 8 != pos + 32);
	*(__le32 *)(out + destsize * vcnt - 4) = cpu_to_le32(*blkaddr_ret);
	*blkaddr_ret = blkaddr;
	return out + destsize * vcnt;
}

int z_erofs_convert_to_compacted_format(struct erofs_inode *inode,
					erofs_off_t pstart,
					unsigned int legacymetasize,
					void *compressmeta)
{
	const unsigned int mpos = roundup(inode->inode_isize +
					  inode->xattr_isize, 8) +
				  sizeof(struct z_erofs_map_header);
	const unsigned int totalidx = (legacymetasize -
			Z_EROFS_LEGACY_MAP_HEADER_SIZE) /
				sizeof(struct z_erofs_lcluster_index);
	const unsigned int logical_clusterbits = inode->z_lclusterbits;
	u8 *out, *in;
	struct z_erofs_compressindex_vec cv[16];
	struct erofs_sb_info *sbi = inode->sbi;
	/* # of 8-byte units so that it can be aligned with 32 bytes */
	unsigned int compacted_4b_initial, compacted_4b_end;
	unsigned int compacted_2b;
	bool dummy_head;
	bool big_pcluster = erofs_sb_has_big_pcluster(sbi);
	erofs_blk_t blkaddr;

	if (logical_clusterbits < sbi->blkszbits)
		return -EINVAL;
	if (pstart & (erofs_blksiz(sbi) - 1))
		return -EINVAL;
	if (logical_clusterbits > 14) {
		erofs_err("compact format is unsupported for lcluster size %u",
			  1 << logical_clusterbits);
		return -EOPNOTSUPP;
	}

	blkaddr = pstart >> sbi->blkszbits;
	if (inode->z_advise & Z_EROFS_ADVISE_COMPACTED_2B) {
		if (logical_clusterbits > 12) {
			erofs_err("compact 2B is unsupported for lcluster size %u",
				  1 << logical_clusterbits);
			return -EINVAL;
		}

		compacted_4b_initial = (32 - mpos % 32) / 4;
		if (compacted_4b_initial == 32 / 4)
			compacted_4b_initial = 0;

		if (compacted_4b_initial > totalidx) {
			compacted_4b_initial = compacted_2b = 0;
			compacted_4b_end = totalidx;
		} else {
			compacted_2b = rounddown(totalidx -
						 compacted_4b_initial, 16);
			compacted_4b_end = totalidx - compacted_4b_initial -
					   compacted_2b;
		}
	} else {
		compacted_2b = compacted_4b_initial = 0;
		compacted_4b_end = totalidx;
	}

	out = in = compressmeta;

	out += sizeof(struct z_erofs_map_header);
	in += Z_EROFS_LEGACY_MAP_HEADER_SIZE;

	dummy_head = false;
	/* prior to bigpcluster, blkaddr was bumped up once coming into HEAD */
	if (!big_pcluster) {
		--blkaddr;
		dummy_head = true;
	}

	/* generate compacted_4b_initial */
	while (compacted_4b_initial) {
		in = parse_legacy_indexes(cv, 2, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      4, logical_clusterbits, false,
					      &dummy_head, big_pcluster);
		compacted_4b_initial -= 2;
	}
	DBG_BUGON(compacted_4b_initial);

	/* generate compacted_2b */
	while (compacted_2b) {
		in = parse_legacy_indexes(cv, 16, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      2, logical_clusterbits, false,
					      &dummy_head, big_pcluster);
		compacted_2b -= 16;
	}
	DBG_BUGON(compacted_2b);

	/* generate compacted_4b_end */
	while (compacted_4b_end > 1) {
		in = parse_legacy_indexes(cv, 2, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      4, logical_clusterbits, false,
					      &dummy_head, big_pcluster);
		compacted_4b_end -= 2;
	}

	/* generate final compacted_4b_end if needed */
	if (compacted_4b_end) {
		memset(cv, 0, sizeof(cv));
		in = parse_legacy_indexes(cv, 1, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      4, logical_clusterbits, true,
					      &dummy_head, big_pcluster);
	}
	inode->extent_isize = out - (u8 *)compressmeta;
	return 0;
}

static void z_erofs_write_mapheader(struct erofs_inode *inode,
				    void *compressmeta)
{
	struct erofs_sb_info *sbi = inode->sbi;
	struct z_erofs_map_header h;

	if (inode->datalayout == EROFS_INODE_COMPRESSED_FULL &&
	    (inode->z_advise & Z_EROFS_ADVISE_EXTENTS)) {
		int recsz = z_erofs_extent_recsize(inode->z_advise);

		if (recsz > offsetof(struct z_erofs_extent, pstart_hi)) {
			h = (struct z_erofs_map_header) {
				.h_advise = cpu_to_le16(inode->z_advise),
				.h_extents_lo = cpu_to_le32(inode->z_extents),
			};
		} else {
			DBG_BUGON(inode->z_lclusterbits < sbi->blkszbits);
			h = (struct z_erofs_map_header) {
				.h_advise = cpu_to_le16(inode->z_advise),
				.h_clusterbits = inode->z_lclusterbits - sbi->blkszbits,
			};
		}
	} else {
		h = (struct z_erofs_map_header) {
			.h_advise = cpu_to_le16(inode->z_advise),
			.h_algorithmtype = inode->z_algorithmtype[1] << 4 |
					   inode->z_algorithmtype[0],
			/* lclustersize */
			.h_clusterbits = inode->z_lclusterbits - sbi->blkszbits,
		};
		if (inode->z_advise & Z_EROFS_ADVISE_FRAGMENT_PCLUSTER)
			h.h_fragmentoff = cpu_to_le32(inode->fragmentoff);
		else
			h.h_idata_size = cpu_to_le16(inode->idata_size);

		memset(compressmeta, 0, Z_EROFS_LEGACY_MAP_HEADER_SIZE);
	}
	/* write out map header */
	memcpy(compressmeta, &h, sizeof(struct z_erofs_map_header));
}

#define EROFS_FULL_INDEXES_SZ(inode)	\
	(BLK_ROUND_UP(inode->sbi, inode->i_size) * \
	 sizeof(struct z_erofs_lcluster_index) + Z_EROFS_LEGACY_MAP_HEADER_SIZE)

static void *z_erofs_write_extents(struct z_erofs_compress_ictx *ctx)
{
	struct erofs_inode *inode = ctx->inode;
	struct erofs_sb_info *sbi = inode->sbi;
	struct z_erofs_extent_item *ei, *n;
	unsigned int lclusterbits, nexts;
	bool pstart_hi = false, unaligned_data = false;
	erofs_off_t pstart, pend, lstart;
	unsigned int recsz, metasz, moff;
	void *metabuf;

	ei = list_first_entry(&ctx->extents, struct z_erofs_extent_item,
			      list);
	lclusterbits = max_t(u8, ilog2(ei->e.length - 1) + 1, sbi->blkszbits);
	pend = pstart = ei->e.pstart;
	nexts = 0;
	list_for_each_entry(ei, &ctx->extents, list) {
		pstart_hi |= (ei->e.pstart > UINT32_MAX);
		if ((ei->e.pstart | ei->e.plen) & ((1U << sbi->blkszbits) - 1))
			unaligned_data = true;
		if (pend != ei->e.pstart)
			pend = EROFS_NULL_ADDR;
		else
			pend += ei->e.plen;
		if (ei->e.length != 1 << lclusterbits) {
			if (ei->list.next != &ctx->extents ||
			    ei->e.length > 1 << lclusterbits)
				lclusterbits = 0;
		}
		++nexts;
	}

	recsz = inode->i_size > UINT32_MAX ? 32 : 16;
	if (lclusterbits) {
		if (pend != EROFS_NULL_ADDR)
			recsz = 4;
		else if (recsz <= 16 && !pstart_hi)
			recsz = 8;
	}

	moff = Z_EROFS_MAP_HEADER_END(inode->inode_isize + inode->xattr_isize);
	moff = round_up(moff, recsz) -
		Z_EROFS_MAP_HEADER_START(inode->inode_isize + inode->xattr_isize);
	metasz = moff + recsz * nexts + 8 * (recsz <= 4);
	if (!unaligned_data && metasz > EROFS_FULL_INDEXES_SZ(inode))
		return ERR_PTR(-EAGAIN);

	metabuf = malloc(metasz);
	if (!metabuf)
		return ERR_PTR(-ENOMEM);
	inode->z_lclusterbits = lclusterbits;
	inode->z_extents = nexts;
	ctx->metacur = metabuf + moff;
	if (recsz <= 4) {
		*(__le64 *)ctx->metacur	= cpu_to_le64(pstart);
		ctx->metacur += sizeof(__le64);
	}

	nexts = 0;
	lstart = 0;
	list_for_each_entry_safe(ei, n, &ctx->extents, list) {
		struct z_erofs_extent de;
		u32 fmt, plen;

		plen = ei->e.plen;
		if (!plen) {
			plen = inode->fragmentoff;
			ei->e.pstart = inode->fragmentoff >> 32;
		} else {
			fmt = ei->e.raw ? 0 : inode->z_algorithmtype[0] + 1;
			plen |= fmt << Z_EROFS_EXTENT_PLEN_FMT_BIT;
			if (ei->e.partial)
				plen |= Z_EROFS_EXTENT_PLEN_PARTIAL;
		}
		de = (struct z_erofs_extent) {
			.plen = cpu_to_le32(plen),
			.pstart_lo = cpu_to_le32(ei->e.pstart),
			.lstart_lo = cpu_to_le32(lstart),
			.pstart_hi = cpu_to_le32(ei->e.pstart >> 32),
			.lstart_hi = cpu_to_le32(lstart >> 32),
		};
		memcpy(ctx->metacur, &de, recsz);
		ctx->metacur += recsz;
		lstart += ei->e.length;
		list_del(&ei->list);
		free(ei);
	}
	inode->datalayout = EROFS_INODE_COMPRESSED_FULL;
	inode->z_advise |= Z_EROFS_ADVISE_EXTENTS |
		((ilog2(recsz) - 2) << Z_EROFS_ADVISE_EXTRECSZ_BIT);
	return metabuf;
}

static void *z_erofs_write_indexes(struct z_erofs_compress_ictx *ctx)
{
	struct erofs_inode *inode = ctx->inode;
	struct erofs_sb_info *sbi = inode->sbi;
	struct z_erofs_extent_item *ei, *n;
	void *metabuf;

	/* TODO: support writing encoded extents for ztailpacking later. */
	if (erofs_sb_has_48bit(sbi) && !inode->idata_size) {
		metabuf = z_erofs_write_extents(ctx);
		if (metabuf != ERR_PTR(-EAGAIN)) {
			if (IS_ERR(metabuf))
				return metabuf;
			goto out;
		}
	}

	/*
	 * If the packed inode is larger than 4GiB, the full fragmentoff
	 * will be recorded by switching to the noncompact layout anyway.
	 */
	if (inode->fragment_size && inode->fragmentoff >> 32) {
		inode->datalayout = EROFS_INODE_COMPRESSED_FULL;
	} else if (!cfg.c_legacy_compress && !ctx->dedupe &&
		   inode->z_lclusterbits <= 14) {
		if (inode->z_lclusterbits <= 12)
			inode->z_advise |= Z_EROFS_ADVISE_COMPACTED_2B;
		inode->datalayout = EROFS_INODE_COMPRESSED_COMPACT;
	} else {
		inode->datalayout = EROFS_INODE_COMPRESSED_FULL;
	}

	if (erofs_sb_has_big_pcluster(sbi)) {
		inode->z_advise |= Z_EROFS_ADVISE_BIG_PCLUSTER_1;
		if (inode->datalayout == EROFS_INODE_COMPRESSED_COMPACT)
			inode->z_advise |= Z_EROFS_ADVISE_BIG_PCLUSTER_2;
	}

	metabuf = malloc(BLK_ROUND_UP(inode->sbi, inode->i_size) *
			 sizeof(struct z_erofs_lcluster_index) +
			 Z_EROFS_LEGACY_MAP_HEADER_SIZE);
	if (!metabuf)
		return ERR_PTR(-ENOMEM);

	ctx->metacur = metabuf + Z_EROFS_LEGACY_MAP_HEADER_SIZE;
	ctx->clusterofs = 0;
	list_for_each_entry_safe(ei, n, &ctx->extents, list) {
		DBG_BUGON(ei->list.next != &ctx->extents &&
			  ctx->clusterofs + ei->e.length < erofs_blksiz(sbi));
		z_erofs_write_full_indexes(ctx, &ei->e);

		list_del(&ei->list);
		free(ei);
	}
	z_erofs_fini_full_indexes(ctx);
out:
	z_erofs_write_mapheader(inode, metabuf);
	return metabuf;
}

void z_erofs_drop_inline_pcluster(struct erofs_inode *inode)
{
	struct erofs_sb_info *sbi = inode->sbi;
	const unsigned int type = Z_EROFS_LCLUSTER_TYPE_PLAIN;
	struct z_erofs_map_header *h = inode->compressmeta;

	h->h_advise = cpu_to_le16(le16_to_cpu(h->h_advise) &
				  ~Z_EROFS_ADVISE_INLINE_PCLUSTER);
	h->h_idata_size = 0;
	if (!inode->eof_tailraw)
		return;
	DBG_BUGON(inode->compressed_idata != true);

	/* patch the EOF lcluster to uncompressed type first */
	if (inode->datalayout == EROFS_INODE_COMPRESSED_FULL) {
		struct z_erofs_lcluster_index *di =
			(inode->compressmeta + inode->extent_isize) -
			sizeof(struct z_erofs_lcluster_index);

		di->di_advise = cpu_to_le16(type);
	} else if (inode->datalayout == EROFS_INODE_COMPRESSED_COMPACT) {
		/* handle the last compacted 4B pack */
		unsigned int eofs, base, pos, v, lo;
		u8 *out;

		eofs = inode->extent_isize -
			(4 << (BLK_ROUND_UP(sbi, inode->i_size) & 1));
		base = round_down(eofs, 8);
		pos = 16 /* encodebits */ * ((eofs - base) / 4);
		out = inode->compressmeta + base;
		lo = erofs_blkoff(sbi, get_unaligned_le32(out + pos / 8));
		v = (type << sbi->blkszbits) | lo;
		out[pos / 8] = v & 0xff;
		out[pos / 8 + 1] = v >> 8;
	} else {
		DBG_BUGON(1);
		return;
	}
	free(inode->idata);
	/* replace idata with prepared uncompressed data */
	inode->idata = inode->eof_tailraw;
	inode->idata_size = inode->eof_tailrawsize;
	inode->compressed_idata = false;
	inode->eof_tailraw = NULL;
}

int z_erofs_compress_segment(struct z_erofs_compress_sctx *ctx,
			     u64 offset, erofs_off_t pstart)
{
	struct z_erofs_compress_ictx *ictx = ctx->ictx;
	struct erofs_inode *inode = ictx->inode;
	bool frag = cfg.c_fragments && !erofs_is_packed_inode(inode) &&
		!erofs_is_metabox_inode(inode) &&
		ctx->seg_idx >= ictx->seg_num - 1;
	int fd = ictx->fd;
	int ret;

	DBG_BUGON(offset != -1 && frag && inode->fragment_size);
	if (offset != -1 && frag && !inode->fragment_size &&
	    cfg.c_fragdedupe != FRAGDEDUPE_OFF) {
		ret = erofs_fragment_findmatch(inode, fd, ictx->tofh);
		if (ret < 0)
			return ret;
		if (inode->fragment_size > ctx->remaining)
			inode->fragment_size = ctx->remaining;
		ctx->remaining -= inode->fragment_size;
	}

	ctx->pstart = pstart;
	ctx->poff = 0;
	while (ctx->remaining) {
		const u64 rx = min_t(u64, ctx->remaining,
				     Z_EROFS_COMPR_QUEUE_SZ - ctx->tail);
		int ret;

		ret = (offset == -1 ?
			read(fd, ctx->queue + ctx->tail, rx) :
			pread(fd, ctx->queue + ctx->tail, rx,
			      ictx->fpos + offset));
		if (ret != rx)
			return -errno;

		ctx->remaining -= rx;
		ctx->tail += rx;
		if (offset != -1)
			offset += rx;

		ret = z_erofs_compress_one(ctx);
		if (ret)
			return ret;
	}
	DBG_BUGON(ctx->head != ctx->tail);

	if (ctx->pivot) {
		z_erofs_commit_extent(ctx, ctx->pivot);
		ctx->pivot = NULL;
	}

	/* generate an extra extent for the deduplicated fragment */
	if (frag && inode->fragment_size && !ictx->fragemitted) {
		struct z_erofs_extent_item *ei;

		ei = malloc(sizeof(*ei));
		if (!ei)
			return -ENOMEM;

		ei->e = (struct z_erofs_inmem_extent) {
			.length = inode->fragment_size,
			.plen = 0,
			.raw = false,
			.partial = false,
			.pstart = ctx->pstart,
		};
		init_list_head(&ei->list);
		z_erofs_commit_extent(ctx, ei);
	}
	return 0;
}

int erofs_commit_compressed_file(struct z_erofs_compress_ictx *ictx,
				 struct erofs_buffer_head *bh,
				 erofs_off_t pstart, erofs_off_t ptotal)
{
	struct erofs_inode *inode = ictx->inode;
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int legacymetasize, bbits = sbi->blkszbits;
	u8 *compressmeta;
	int ret;

	if (inode->fragment_size) {
		ret = erofs_fragment_commit(inode, ictx->tofh);
		if (ret)
			goto err_free_idata;
		inode->z_advise |= Z_EROFS_ADVISE_FRAGMENT_PCLUSTER;
		erofs_sb_set_fragments(inode->sbi);
	}

	/* fall back to no compression mode */
	DBG_BUGON(pstart < (!!inode->idata_size) << bbits);
	ptotal -= (u64)(!!inode->idata_size) << bbits;

	compressmeta = z_erofs_write_indexes(ictx);
	if (!compressmeta) {
		ret = -ENOMEM;
		goto err_free_idata;
	}

	legacymetasize = ictx->metacur - compressmeta;
	/* estimate if data compression saves space or not */
	if (!inode->fragment_size && ptotal + inode->idata_size +
	    legacymetasize >= inode->i_size) {
		z_erofs_dedupe_ext_commit(true);
		z_erofs_dedupe_commit(true);
		ret = -ENOSPC;
		goto err_free_meta;
	}
	z_erofs_dedupe_ext_commit(false);
	z_erofs_dedupe_commit(false);

	if (!ictx->fragemitted)
		sbi->saved_by_deduplication += inode->fragment_size;

	/* if the entire file is a fragment, a simplified form is used. */
	if (inode->i_size <= inode->fragment_size) {
		DBG_BUGON(inode->i_size < inode->fragment_size);
		DBG_BUGON(inode->fragmentoff >> 63);
		*(__le64 *)compressmeta =
			cpu_to_le64(inode->fragmentoff | 1ULL << 63);
		inode->datalayout = EROFS_INODE_COMPRESSED_FULL;
		legacymetasize = Z_EROFS_LEGACY_MAP_HEADER_SIZE;
	}

	if (ptotal)
		(void)erofs_bh_balloon(bh, ptotal);
	else if (!cfg.c_fragments && !cfg.c_dedupe)
		DBG_BUGON(!inode->idata_size);

	erofs_info("compressed %s (%llu bytes) into %llu bytes",
		   inode->i_srcpath, inode->i_size | 0ULL, ptotal | 0ULL);

	if (inode->idata_size) {
		bh->op = &erofs_skip_write_bhops;
		inode->bh_data = bh;
	} else {
		erofs_bdrop(bh, false);
	}

	inode->u.i_blocks = BLK_ROUND_UP(sbi, ptotal);

	if (inode->datalayout == EROFS_INODE_COMPRESSED_FULL) {
		inode->extent_isize = legacymetasize;
	} else {
		ret = z_erofs_convert_to_compacted_format(inode, pstart,
							  legacymetasize,
							  compressmeta);
		DBG_BUGON(ret);
	}
	inode->compressmeta = compressmeta;
	return 0;

err_free_meta:
	free(compressmeta);
	inode->compressmeta = NULL;
err_free_idata:
	erofs_bdrop(bh, true);	/* revoke buffer */
	if (inode->idata) {
		free(inode->idata);
		inode->idata = NULL;
	}
	return ret;
}

static struct z_erofs_compress_ictx g_ictx;

#ifdef EROFS_MT_ENABLED
void *z_erofs_mt_wq_tls_alloc(struct erofs_workqueue *wq, void *ptr)
{
	struct erofs_compress_wq_tls *tls;

	tls = calloc(1, sizeof(*tls));
	if (!tls)
		return NULL;

	tls->queue = malloc(Z_EROFS_COMPR_QUEUE_SZ);
	if (!tls->queue)
		goto err_free_priv;

	tls->destbuf = calloc(1, Z_EROFS_DESTBUF_SZ);
	if (!tls->destbuf)
		goto err_free_queue;

	tls->ccfg = calloc(EROFS_MAX_COMPR_CFGS, sizeof(*tls->ccfg));
	if (!tls->ccfg)
		goto err_free_destbuf;
	return tls;

err_free_destbuf:
	free(tls->destbuf);
err_free_queue:
	free(tls->queue);
err_free_priv:
	free(tls);
	return NULL;
}

int z_erofs_mt_wq_tls_init_compr(struct erofs_sb_info *sbi,
				 struct erofs_compress_wq_tls *tls,
				 unsigned int alg_id, char *alg_name,
				 unsigned int comp_level,
				 unsigned int dict_size)
{
	struct erofs_compress_cfg *lc = &tls->ccfg[alg_id];
	int ret;

	if (__erofs_likely(lc->enable))
		return 0;

	ret = erofs_compressor_init(sbi, &lc->handle, alg_name,
				    comp_level, dict_size);
	if (ret)
		return ret;
	lc->algorithmtype = alg_id;
	lc->enable = true;
	return 0;
}

void *z_erofs_mt_wq_tls_free(struct erofs_workqueue *wq, void *priv)
{
	struct erofs_compress_wq_tls *tls = priv;
	int i;

	for (i = 0; i < EROFS_MAX_COMPR_CFGS; i++)
		if (tls->ccfg[i].enable)
			erofs_compressor_exit(&tls->ccfg[i].handle);

	free(tls->ccfg);
	free(tls->destbuf);
	free(tls->queue);
	free(tls);
	return NULL;
}

void z_erofs_mt_workfn(struct erofs_work *work, void *tlsp)
{
	struct erofs_compress_work *cwork = (struct erofs_compress_work *)work;
	struct erofs_compress_wq_tls *tls = tlsp;
	struct z_erofs_compress_sctx *sctx = &cwork->ctx;
	struct z_erofs_compress_ictx *ictx = sctx->ictx;
	struct erofs_inode *inode = ictx->inode;
	struct erofs_sb_info *sbi = inode->sbi;
	int ret = 0;

	ret = z_erofs_mt_wq_tls_init_compr(sbi, tls, cwork->alg_id,
					   cwork->alg_name, cwork->comp_level,
					   cwork->dict_size);
	if (ret)
		goto out;

	sctx->pclustersize = z_erofs_get_max_pclustersize(inode);
	DBG_BUGON(sctx->pclustersize > Z_EROFS_PCLUSTER_MAX_SIZE);
	sctx->queue = tls->queue;
	sctx->destbuf = tls->destbuf;
	sctx->chandle = &tls->ccfg[cwork->alg_id].handle;
	erofs_compressor_reset(sctx->chandle);
	sctx->membuf = malloc(round_up(sctx->remaining, erofs_blksiz(sbi)));
	if (!sctx->membuf) {
		ret = -ENOMEM;
		goto out;
	}
	ret = z_erofs_compress_segment(sctx, sctx->seg_idx * cfg.c_mkfs_segment_size,
				       EROFS_NULL_ADDR);

out:
	DBG_BUGON(ret > 0);
	pthread_mutex_lock(&ictx->mutex);
	cwork->errcode = ret;
	pthread_cond_signal(&cwork->cond);
	pthread_mutex_unlock(&ictx->mutex);
}

void z_erofs_mt_f_workfn(struct erofs_work *work, void *tlsp)
{
	struct erofs_compress_work *cwork = (struct erofs_compress_work *)work;
	struct erofs_sb_info *sbi = cwork->ctx.ictx->inode->sbi;
	u32 tofh = cwork->ctx.ictx->tofh;
	struct z_erofs_compress_fslot *fs = &sbi->zmgr->fslot[tofh & 1023];

	while (1) {
		z_erofs_mt_workfn(work, tlsp);
		pthread_mutex_lock(&fs->lock);

		if (list_empty(&fs->pending)) {
			fs->inprogress = false;
			pthread_mutex_unlock(&fs->lock);
			break;
		}
		cwork = list_first_entry(&fs->pending,
					 struct erofs_compress_work,
					 ctx.sibling);
		list_del(&cwork->ctx.sibling);
		pthread_mutex_unlock(&fs->lock);
		init_list_head(&cwork->ctx.extents);
		work = &cwork->work;
	}
}

int z_erofs_merge_segment(struct z_erofs_compress_ictx *ictx,
			  struct z_erofs_compress_sctx *sctx)
{
	struct z_erofs_extent_item *ei, *n;
	struct erofs_sb_info *sbi = ictx->inode->sbi;
	bool dedupe_ext = cfg.c_fragments;
	erofs_off_t off = 0;
	int ret = 0, ret2;
	erofs_off_t dpo;
	u64 hash;

	list_for_each_entry_safe(ei, n, &sctx->extents, list) {
		list_del(&ei->list);
		list_add_tail(&ei->list, &ictx->extents);

		if (ei->e.pstart != EROFS_NULL_ADDR)	/* deduped extents */
			continue;

		ei->e.pstart = sctx->pstart;
		sctx->pstart += ei->e.plen;

		/* skip write data but leave blkaddr for inline fallback */
		if (ei->e.inlined || !ei->e.plen)
			continue;

		if (dedupe_ext) {
			dpo = z_erofs_dedupe_ext_match(sbi, sctx->membuf + off,
						ei->e.plen, ei->e.raw, &hash);
			if (dpo) {
				ei->e.pstart = dpo;
				sctx->pstart -= ei->e.plen;
				off += ei->e.plen;
				ictx->dedupe = true;
				erofs_sb_set_dedupe(sbi);
				sbi->saved_by_deduplication += ei->e.plen;
				erofs_dbg("Dedupe %u %scompressed data to %llu of %u bytes",
					  ei->e.length, ei->e.raw ? "un" : "",
					  ei->e.pstart | 0ULL, ei->e.plen);
				continue;
			}
		}
		erofs_dbg("Writing %u %scompressed data of %s to %llu", ei->e.length,
			  ei->e.raw ? "un" : "", ictx->inode->i_srcpath, ei->e.pstart);
		ret2 = erofs_dev_write(sbi, sctx->membuf + off, ei->e.pstart,
				       ei->e.plen);
		off += ei->e.plen;
		if (ret2)
			ret = ret2;
		else if (dedupe_ext)
			z_erofs_dedupe_ext_insert(&ei->e, hash);
	}
	free(sctx->membuf);
	sctx->membuf = NULL;
	return ret;
}

int z_erofs_mt_compress(struct z_erofs_compress_ictx *ictx)
{
	struct erofs_compress_work *cur, *head = NULL, **last = &head;
	struct erofs_compress_cfg *ccfg = ictx->ccfg;
	struct erofs_inode *inode = ictx->inode;
	unsigned int segsz = cfg.c_mkfs_segment_size;
	int nsegs, i;

	nsegs = DIV_ROUND_UP(inode->i_size - inode->fragment_size, segsz);
	if (!nsegs)
		nsegs = 1;
	ictx->seg_num = nsegs;
	pthread_mutex_init(&ictx->mutex, NULL);
	pthread_cond_init(&ictx->cond, NULL);

	for (i = 0; i < nsegs; i++) {
		pthread_mutex_lock(&z_erofs_mt_ctrl.mutex);
		cur = z_erofs_mt_ctrl.idle;
		if (cur) {
			z_erofs_mt_ctrl.idle = cur->next;
			cur->next = NULL;
		}
		pthread_mutex_unlock(&z_erofs_mt_ctrl.mutex);
		if (!cur) {
			cur = calloc(1, sizeof(*cur));
			if (!cur)
				return -ENOMEM;
			pthread_cond_init(&cur->cond, NULL);
		}
		*last = cur;
		last = &cur->next;

		cur->ctx = (struct z_erofs_compress_sctx) {
			.ictx = ictx,
			.seg_idx = i,
			.pivot = &dummy_pivot,
		};
		init_list_head(&cur->ctx.extents);

		cur->alg_id = ccfg->handle.alg->id;
		cur->alg_name = ccfg->handle.alg->name;
		cur->comp_level = ccfg->handle.compression_level;
		cur->dict_size = ccfg->handle.dict_size;
		cur->errcode = 1;	/* mark as "in progress" */

		if (i >= nsegs - 1) {
			cur->ctx.remaining = inode->i_size -
					inode->fragment_size - (u64)i * segsz;

			if (z_erofs_mt_ctrl.hasfwq && ictx->tofh != ~0U) {
				struct z_erofs_mgr *zmgr = inode->sbi->zmgr;
				struct z_erofs_compress_fslot *fs =
					&zmgr->fslot[ictx->tofh & 1023];

				pthread_mutex_lock(&fs->lock);
				if (fs->inprogress) {
					list_add_tail(&cur->ctx.sibling,
						      &fs->pending);
				} else {
					fs->inprogress = true;
					cur->work.fn = z_erofs_mt_f_workfn;
					erofs_queue_work(&z_erofs_mt_ctrl.wq,
						 &cur->work);
				}
				pthread_mutex_unlock(&fs->lock);
				continue;
			}
		} else {
			cur->ctx.remaining = segsz;
		}
		cur->work.fn = z_erofs_mt_workfn;
		erofs_queue_work(&z_erofs_mt_ctrl.wq, &cur->work);
	}
	ictx->mtworks = head;
	return 0;
}

int erofs_mt_write_compressed_file(struct z_erofs_compress_ictx *ictx)
{
	struct erofs_sb_info *sbi = ictx->inode->sbi;
	struct erofs_buffer_head *bh = NULL;
	struct erofs_compress_work *head = ictx->mtworks, *cur;
	erofs_off_t pstart, ptotal = 0;
	int ret;

	bh = erofs_balloc(sbi->bmgr, DATA, 0, 0);
	if (IS_ERR(bh)) {
		ret = PTR_ERR(bh);
		goto out;
	}

	DBG_BUGON(!head);
	pstart = erofs_pos(sbi, erofs_mapbh(NULL, bh->block));

	ret = 0;
	do {
		cur = head;
		head = cur->next;

		pthread_mutex_lock(&ictx->mutex);
		while ((ret = cur->errcode) > 0)
			pthread_cond_wait(&cur->cond, &ictx->mutex);
		pthread_mutex_unlock(&ictx->mutex);

		if (!ret) {
			int ret2;

			cur->ctx.pstart = pstart;
			ret2 = z_erofs_merge_segment(ictx, &cur->ctx);
			if (ret2)
				ret = ret2;

			ptotal += cur->ctx.pstart - pstart;
			pstart = cur->ctx.pstart;
		}

		pthread_mutex_lock(&z_erofs_mt_ctrl.mutex);
		cur->next = z_erofs_mt_ctrl.idle;
		z_erofs_mt_ctrl.idle = cur;
		pthread_mutex_unlock(&z_erofs_mt_ctrl.mutex);
	} while (head);

	if (ret)
		goto out;
	ret = erofs_commit_compressed_file(ictx, bh, pstart - ptotal, ptotal);

out:
	free(ictx);
	return ret;
}

static int z_erofs_mt_init(void)
{
	unsigned int workers = cfg.c_mt_workers;
	int ret;

	if (workers < 1)
		return 0;
	if (workers >= 1 && cfg.c_dedupe) {
		erofs_warn("multi-threaded dedupe is NOT implemented for now");
		cfg.c_mt_workers = 0;
	} else {
		if (cfg.c_fragments && workers > 1)
			z_erofs_mt_ctrl.hasfwq = true;

		ret = erofs_alloc_workqueue(&z_erofs_mt_ctrl.wq, workers,
					    workers << 2,
					    z_erofs_mt_wq_tls_alloc,
					    z_erofs_mt_wq_tls_free);
		if (ret)
			return ret;
		z_erofs_mt_enabled = true;
	}
	pthread_mutex_init(&g_ictx.mutex, NULL);
	pthread_cond_init(&g_ictx.cond, NULL);
	return 0;
}
#else
static int z_erofs_mt_init(void)
{
	return 0;
}
#endif

void *erofs_begin_compressed_file(struct erofs_inode *inode, int fd, u64 fpos)
{
	struct erofs_sb_info *sbi = inode->sbi;
	struct z_erofs_compress_ictx *ictx;
	bool frag = cfg.c_fragments && !erofs_is_packed_inode(inode) &&
		!erofs_is_metabox_inode(inode);
	bool all_fragments = cfg.c_all_fragments && frag;
	int ret;

	/* initialize per-file compression setting */
	inode->z_advise = 0;
	inode->z_lclusterbits = sbi->blkszbits;
#ifndef NDEBUG
	if (cfg.c_random_algorithms) {
		while (1) {
			inode->z_algorithmtype[0] =
				rand() % EROFS_MAX_COMPR_CFGS;
			if (sbi->zmgr->ccfg[inode->z_algorithmtype[0]].enable)
				break;
		}
	}
#endif
	inode->idata_size = 0;
	inode->fragment_size = 0;

	if (!z_erofs_mt_enabled || all_fragments) {
#ifdef EROFS_MT_ENABLED
		pthread_mutex_lock(&g_ictx.mutex);
		if (g_ictx.seg_num)
			pthread_cond_wait(&g_ictx.cond, &g_ictx.mutex);
		g_ictx.seg_num = 1;
		pthread_mutex_unlock(&g_ictx.mutex);
#endif
		ictx = &g_ictx;
	} else {
		ictx = malloc(sizeof(*ictx));
		if (!ictx)
			return ERR_PTR(-ENOMEM);
	}
	ictx->fd = fd;
	if (erofs_is_metabox_inode(inode))
		ictx->ccfg = &sbi->zmgr->ccfg[cfg.c_mkfs_metabox_algid];
	else
		ictx->ccfg = &sbi->zmgr->ccfg[inode->z_algorithmtype[0]];
	inode->z_algorithmtype[0] = ictx->ccfg->algorithmtype;
	inode->z_algorithmtype[1] = 0;
	ictx->data_unaligned = erofs_sb_has_48bit(sbi) &&
		cfg.c_max_decompressed_extent_bytes <=
			z_erofs_get_max_pclustersize(inode);
	if (cfg.c_fragments && !cfg.c_dedupe && !ictx->data_unaligned)
		inode->z_advise |= Z_EROFS_ADVISE_INTERLACED_PCLUSTER;

	if (frag) {
		ictx->tofh = z_erofs_fragments_tofh(inode, fd, fpos);
		if (ictx == &g_ictx && cfg.c_fragdedupe != FRAGDEDUPE_OFF) {
			/*
			 * Handle tails in advance to avoid writing duplicated
			 * parts into the packed inode.
			 */
			ret = erofs_fragment_findmatch(inode, fd, ictx->tofh);
			if (ret < 0)
				goto err_free_ictx;

			if (cfg.c_fragdedupe == FRAGDEDUPE_INODE &&
			    inode->fragment_size < inode->i_size) {
				erofs_dbg("Discard the sub-inode tail fragment of %s",
					  inode->i_srcpath);
				inode->fragment_size = 0;
			}
		}
	}
	ictx->inode = inode;
	ictx->fpos = fpos;
	init_list_head(&ictx->extents);
	ictx->fix_dedupedfrag = false;
	ictx->fragemitted = false;
	ictx->dedupe = false;

	if (all_fragments && !inode->fragment_size) {
		ret = erofs_pack_file_from_fd(inode, fd, ictx->tofh);
		if (ret)
			goto err_free_idata;
	}
#ifdef EROFS_MT_ENABLED
	if (ictx != &g_ictx) {
		ret = z_erofs_mt_compress(ictx);
		if (ret)
			goto err_free_idata;
	}
#endif
	return ictx;

err_free_idata:
	if (inode->idata) {
		free(inode->idata);
		inode->idata = NULL;
	}
err_free_ictx:
	if (ictx != &g_ictx)
		free(ictx);
	return ERR_PTR(ret);
}

int erofs_write_compressed_file(struct z_erofs_compress_ictx *ictx)
{
	static u8 g_queue[Z_EROFS_COMPR_QUEUE_SZ];
	struct erofs_buffer_head *bh;
	static struct z_erofs_compress_sctx sctx;
	struct erofs_compress_cfg *ccfg = ictx->ccfg;
	struct erofs_inode *inode = ictx->inode;
	struct erofs_sb_info *sbi = inode->sbi;
	erofs_off_t pstart;
	int ret;

#ifdef EROFS_MT_ENABLED
	if (ictx != &g_ictx)
		return erofs_mt_write_compressed_file(ictx);
#endif

	/* allocate main data buffer */
	bh = erofs_balloc(inode->sbi->bmgr, DATA, 0, 0);
	if (IS_ERR(bh)) {
		ret = PTR_ERR(bh);
		goto err_free_idata;
	}
	pstart = erofs_pos(sbi, erofs_mapbh(NULL, bh->block));

	ictx->seg_num = 1;
	sctx = (struct z_erofs_compress_sctx) {
		.ictx = ictx,
		.queue = g_queue,
		.chandle = &ccfg->handle,
		.remaining = inode->i_size - inode->fragment_size,
		.seg_idx = 0,
		.pivot = &dummy_pivot,
		.pclustersize = z_erofs_get_max_pclustersize(inode),
	};
	init_list_head(&sctx.extents);

	ret = z_erofs_compress_segment(&sctx, -1, pstart);
	if (ret)
		goto err_free_idata;

	list_splice_tail(&sctx.extents, &ictx->extents);
	ret = erofs_commit_compressed_file(ictx, bh, pstart,
					   sctx.pstart - pstart);
	goto out;

err_free_idata:
	erofs_bdrop(bh, true);	/* revoke buffer */
	if (inode->idata) {
		free(inode->idata);
		inode->idata = NULL;
	}
out:
#ifdef EROFS_MT_ENABLED
	pthread_mutex_lock(&ictx->mutex);
	ictx->seg_num = 0;
	pthread_cond_signal(&ictx->cond);
	pthread_mutex_unlock(&ictx->mutex);
#endif
	return ret;
}

static int z_erofs_build_compr_cfgs(struct erofs_sb_info *sbi,
				    struct erofs_buffer_head *sb_bh,
				    u32 *max_dict_size)
{
	struct erofs_buffer_head *bh = sb_bh;
	int ret = 0;

	if (sbi->available_compr_algs & (1 << Z_EROFS_COMPRESSION_LZ4)) {
		struct {
			__le16 size;
			struct z_erofs_lz4_cfgs lz4;
		} __packed lz4alg = {
			.size = cpu_to_le16(sizeof(struct z_erofs_lz4_cfgs)),
			.lz4 = {
				.max_distance =
					cpu_to_le16(sbi->lz4.max_distance),
				.max_pclusterblks =
					cfg.c_mkfs_pclustersize_max >> sbi->blkszbits,
			}
		};

		bh = erofs_battach(bh, META, sizeof(lz4alg));
		if (IS_ERR(bh)) {
			DBG_BUGON(1);
			return PTR_ERR(bh);
		}
		erofs_mapbh(NULL, bh->block);
		ret = erofs_dev_write(sbi, &lz4alg, erofs_btell(bh, false),
				      sizeof(lz4alg));
		bh->op = &erofs_drop_directly_bhops;
	}
#ifdef HAVE_LIBLZMA
	if (sbi->available_compr_algs & (1 << Z_EROFS_COMPRESSION_LZMA)) {
		struct {
			__le16 size;
			struct z_erofs_lzma_cfgs lzma;
		} __packed lzmaalg = {
			.size = cpu_to_le16(sizeof(struct z_erofs_lzma_cfgs)),
			.lzma = {
				.dict_size = cpu_to_le32(
					max_dict_size
						[Z_EROFS_COMPRESSION_LZMA]),
			}
		};

		bh = erofs_battach(bh, META, sizeof(lzmaalg));
		if (IS_ERR(bh)) {
			DBG_BUGON(1);
			return PTR_ERR(bh);
		}
		erofs_mapbh(NULL, bh->block);
		ret = erofs_dev_write(sbi, &lzmaalg, erofs_btell(bh, false),
				      sizeof(lzmaalg));
		bh->op = &erofs_drop_directly_bhops;
	}
#endif
	if (sbi->available_compr_algs & (1 << Z_EROFS_COMPRESSION_DEFLATE)) {
		struct {
			__le16 size;
			struct z_erofs_deflate_cfgs z;
		} __packed zalg = {
			.size = cpu_to_le16(sizeof(struct z_erofs_deflate_cfgs)),
			.z = {
				.windowbits = cpu_to_le32(ilog2(
					max_dict_size
						[Z_EROFS_COMPRESSION_DEFLATE])),
			}
		};

		bh = erofs_battach(bh, META, sizeof(zalg));
		if (IS_ERR(bh)) {
			DBG_BUGON(1);
			return PTR_ERR(bh);
		}
		erofs_mapbh(NULL, bh->block);
		ret = erofs_dev_write(sbi, &zalg, erofs_btell(bh, false),
				      sizeof(zalg));
		bh->op = &erofs_drop_directly_bhops;
	}
#ifdef HAVE_LIBZSTD
	if (sbi->available_compr_algs & (1 << Z_EROFS_COMPRESSION_ZSTD)) {
		struct {
			__le16 size;
			struct z_erofs_zstd_cfgs z;
		} __packed zalg = {
			.size = cpu_to_le16(sizeof(struct z_erofs_zstd_cfgs)),
			.z = {
				.windowlog =
					ilog2(max_dict_size[Z_EROFS_COMPRESSION_ZSTD]) - 10,
			}
		};

		bh = erofs_battach(bh, META, sizeof(zalg));
		if (IS_ERR(bh)) {
			DBG_BUGON(1);
			return PTR_ERR(bh);
		}
		erofs_mapbh(NULL, bh->block);
		ret = erofs_dev_write(sbi, &zalg, erofs_btell(bh, false),
				      sizeof(zalg));
		bh->op = &erofs_drop_directly_bhops;
	}
#endif
	return ret;
}

int z_erofs_compress_init(struct erofs_sb_info *sbi)
{
	struct erofs_buffer_head *sb_bh = sbi->bh_sb;
	u32 max_dict_size[Z_EROFS_COMPRESSION_MAX] = {};
	u32 available_compr_algs = 0;
	int i, ret, id;

	if (!sbi->zmgr) {
		sbi->zmgr = calloc(1, sizeof(*sbi->zmgr));
		if (!sbi->zmgr)
			return -ENOMEM;
	}

	for (i = 0; cfg.c_compr_opts[i].alg; ++i) {
		struct erofs_compress_cfg *ccfg = &sbi->zmgr->ccfg[i];
		struct erofs_compress *c = &ccfg->handle;

		ret = erofs_compressor_init(sbi, c, cfg.c_compr_opts[i].alg,
					    cfg.c_compr_opts[i].level,
					    cfg.c_compr_opts[i].dict_size);
		if (ret)
			return ret;

		id = z_erofs_get_compress_algorithm_id(c);
		ccfg->algorithmtype = id;
		ccfg->enable = true;
		available_compr_algs |= 1 << ccfg->algorithmtype;
		if (ccfg->algorithmtype != Z_EROFS_COMPRESSION_LZ4)
			erofs_sb_set_compr_cfgs(sbi);
		if (c->dict_size > max_dict_size[id])
			max_dict_size[id] = c->dict_size;
	}

	/*
	 * if primary algorithm is empty (e.g. compression off),
	 * clear 0PADDING feature for old kernel compatibility.
	 */
	if (!available_compr_algs ||
	    (cfg.c_legacy_compress && available_compr_algs == 1))
		erofs_sb_clear_lz4_0padding(sbi);

	if (!available_compr_algs)
		return 0;

	if (!sb_bh) {
		u32 dalg = available_compr_algs & (~sbi->available_compr_algs);

		if (dalg) {
			erofs_err("unavailable algorithms 0x%x on incremental builds",
				  dalg);
			return -EOPNOTSUPP;
		}
		if (available_compr_algs & (1 << Z_EROFS_COMPRESSION_LZ4) &&
		    sbi->lz4.max_pclusterblks << sbi->blkszbits <
			cfg.c_mkfs_pclustersize_max) {
			erofs_err("pclustersize %u is too large on incremental builds",
				  cfg.c_mkfs_pclustersize_max);
			return -EOPNOTSUPP;
		}
	} else {
		sbi->available_compr_algs = available_compr_algs;
	}

	/*
	 * if big pcluster is enabled, an extra CBLKCNT lcluster index needs
	 * to be loaded in order to get those compressed block counts.
	 */
	if (cfg.c_mkfs_pclustersize_max > erofs_blksiz(sbi)) {
		if (cfg.c_mkfs_pclustersize_max > Z_EROFS_PCLUSTER_MAX_SIZE) {
			erofs_err("unsupported pclustersize %u (too large)",
				  cfg.c_mkfs_pclustersize_max);
			return -EINVAL;
		}
		erofs_sb_set_big_pcluster(sbi);
	}
	if (cfg.c_mkfs_pclustersize_packed > cfg.c_mkfs_pclustersize_max) {
		erofs_err("invalid pclustersize for the packed file %u",
			  cfg.c_mkfs_pclustersize_packed);
		return -EINVAL;
	}

	if (cfg.c_mkfs_pclustersize_metabox > (s32)cfg.c_mkfs_pclustersize_max) {
		erofs_err("invalid pclustersize for the metabox file %u",
			  cfg.c_mkfs_pclustersize_metabox);
		return -EINVAL;
	}

	if (sb_bh && erofs_sb_has_compr_cfgs(sbi)) {
		ret = z_erofs_build_compr_cfgs(sbi, sb_bh, max_dict_size);
		if (ret)
			return ret;
	}

	z_erofs_mt_enabled = false;
	ret = z_erofs_mt_init();
	if (ret)
		return ret;

#ifdef EROFS_MT_ENABLED
	if (z_erofs_mt_ctrl.hasfwq) {
		for (i = 0; i < ARRAY_SIZE(sbi->zmgr->fslot); ++i) {
			init_list_head(&sbi->zmgr->fslot[i].pending);
			pthread_mutex_init(&sbi->zmgr->fslot[i].lock, NULL);
		}
	}
#endif
	return 0;
}

int z_erofs_compress_exit(struct erofs_sb_info *sbi)
{
	int i, ret;

	/* If `zmgr` is uninitialized, return directly. */
	if (!sbi->zmgr)
		return 0;

	for (i = 0; cfg.c_compr_opts[i].alg; ++i) {
		ret = erofs_compressor_exit(&sbi->zmgr->ccfg[i].handle);
		if (ret)
			return ret;
	}

	if (z_erofs_mt_enabled) {
#ifdef EROFS_MT_ENABLED
		ret = erofs_destroy_workqueue(&z_erofs_mt_ctrl.wq);
		if (ret)
			return ret;
		while (z_erofs_mt_ctrl.idle) {
			struct erofs_compress_work *tmp =
				z_erofs_mt_ctrl.idle->next;
			free(z_erofs_mt_ctrl.idle);
			z_erofs_mt_ctrl.idle = tmp;
		}
#endif
	}
	return 0;
}
