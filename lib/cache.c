// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Miao Xie <miaoxie@huawei.com>
 * with heavy changes by Gao Xiang <xiang@kernel.org>
 */
#include <stdlib.h>
#include <erofs/cache.h>
#include "erofs/print.h"

static int erofs_bh_flush_drop_directly(struct erofs_buffer_head *bh)
{
	return erofs_bh_flush_generic_end(bh);
}

const struct erofs_bhops erofs_drop_directly_bhops = {
	.flush = erofs_bh_flush_drop_directly,
};

static int erofs_bh_flush_skip_write(struct erofs_buffer_head *bh)
{
	return -EBUSY;
}

const struct erofs_bhops erofs_skip_write_bhops = {
	.flush = erofs_bh_flush_skip_write,
};

struct erofs_bufmgr *erofs_buffer_init(struct erofs_sb_info *sbi,
				       erofs_blk_t startblk)
{
	struct erofs_bufmgr *bmgr;
	int i, j;

	bmgr = malloc(sizeof(struct erofs_bufmgr));
	if (!bmgr)
		return NULL;

	init_list_head(&bmgr->blkh.list);
	bmgr->blkh.blkaddr = EROFS_NULL_ADDR;
	bmgr->last_mapped_block = &bmgr->blkh;

	for (i = 0; i < ARRAY_SIZE(bmgr->mapped_buckets); i++)
		for (j = 0; j < ARRAY_SIZE(bmgr->mapped_buckets[0]); j++)
			init_list_head(&bmgr->mapped_buckets[i][j]);
	bmgr->tail_blkaddr = startblk;
	bmgr->sbi = sbi;
	bmgr->metablkcnt = 0;
	return bmgr;
}

static void erofs_bupdate_mapped(struct erofs_buffer_block *bb)
{
	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
	struct erofs_sb_info *sbi = bmgr->sbi;
	struct list_head *bkt;

	if (bb->blkaddr == EROFS_NULL_ADDR)
		return;

	bkt = bmgr->mapped_buckets[bb->type] +
		(bb->buffers.off & (erofs_blksiz(sbi) - 1));
	list_del(&bb->mapped_list);
	list_add_tail(&bb->mapped_list, bkt);
}

/* return occupied bytes in specific buffer block if succeed */
static int __erofs_battach(struct erofs_buffer_block *bb,
			   struct erofs_buffer_head *bh,
			   erofs_off_t incr,
			   unsigned int alignsize,
			   unsigned int inline_ext,
			   bool dryrun)
{
	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
	struct erofs_sb_info *sbi = bmgr->sbi;
	const unsigned int blkmask = erofs_blksiz(sbi) - 1;
	erofs_off_t boff = bb->buffers.off;
	const erofs_off_t alignedoffset = roundup(boff, alignsize);
	bool tailupdate = false;
	erofs_blk_t blkaddr;
	int oob;

	/* inline data must never span block boundaries */
	if (erofs_blkoff(sbi, alignedoffset + incr + blkmask)
			+ inline_ext > blkmask)
		return -ENOSPC;

	oob = cmpsgn(roundup(boff, alignsize) + incr + inline_ext,
		     bb->buffers.nblocks << sbi->blkszbits);
	if (oob >= 0) {
		/* the next buffer block should be EROFS_NULL_ADDR all the time */
		if (oob && list_next_entry(bb, list)->blkaddr != EROFS_NULL_ADDR)
			return -EINVAL;

		blkaddr = bb->blkaddr;
		if (blkaddr != EROFS_NULL_ADDR) {
			tailupdate = (bmgr->tail_blkaddr == blkaddr +
				      bb->buffers.nblocks);
			if (oob && !tailupdate)
				return -EINVAL;
		}
	}

	if (!dryrun) {
		if (bh) {
			bh->off = alignedoffset;
			bh->block = bb;
			list_add_tail(&bh->list, &bb->buffers.list);
		}
		boff = alignedoffset + incr;
		bb->buffers.off = boff;
		bb->buffers.nblocks = max_t(erofs_blk_t, bb->buffers.nblocks,
					    BLK_ROUND_UP(sbi, boff));
		/* need to update the tail_blkaddr */
		if (tailupdate)
			bmgr->tail_blkaddr = blkaddr + bb->buffers.nblocks;
		erofs_bupdate_mapped(bb);
	}
	return ((alignedoffset + incr + blkmask) & blkmask) + 1;
}

int erofs_bh_balloon(struct erofs_buffer_head *bh, erofs_off_t incr)
{
	struct erofs_buffer_block *const bb = bh->block;

	/* should be the tail bh in the corresponding buffer block */
	if (bh->list.next != &bb->buffers.list)
		return -EINVAL;

	return __erofs_battach(bb, NULL, incr, 1, 0, false);
}

static int erofs_bfind_for_attach(struct erofs_bufmgr *bmgr,
				  int type, erofs_off_t size,
				  unsigned int inline_ext,
				  unsigned int alignsize,
				  struct erofs_buffer_block **bbp)
{
	const unsigned int blksiz = erofs_blksiz(bmgr->sbi);
	struct erofs_buffer_block *cur, *bb;
	unsigned int used0, used_before, usedmax, used;
	int ret;

	used0 = (size & (blksiz - 1)) + inline_ext;
	/* inline data should be in the same fs block */
	if (used0 > blksiz)
		return -ENOSPC;

	if (!used0 || alignsize == blksiz) {
		*bbp = NULL;
		return 0;
	}

	usedmax = 0;
	bb = NULL;

	/* try to find a most-fit mapped buffer block first */
	if (size + inline_ext >= blksiz)
		goto skip_mapped;

	used_before = rounddown(blksiz - (size + inline_ext), alignsize);
	for (; used_before; --used_before) {
		struct list_head *bt = bmgr->mapped_buckets[type] + used_before;

		if (list_empty(bt))
			continue;
		cur = list_first_entry(bt, struct erofs_buffer_block,
				       mapped_list);

		/* last mapped block can be expended, don't handle it here */
		if (list_next_entry(cur, list)->blkaddr == EROFS_NULL_ADDR) {
			DBG_BUGON(cur != bmgr->last_mapped_block);
			continue;
		}

		DBG_BUGON(cur->type != type);
		DBG_BUGON(cur->blkaddr == EROFS_NULL_ADDR);
		DBG_BUGON(used_before != (cur->buffers.off & (blksiz - 1)));

		ret = __erofs_battach(cur, NULL, size, alignsize,
				      inline_ext, true);
		if (ret < 0) {
			DBG_BUGON(1);
			continue;
		}

		usedmax = ret + inline_ext;
		/* should contain all data in the current block */
		DBG_BUGON(usedmax > blksiz);
		bb = cur;
		break;
	}

skip_mapped:
	/* try to start from the last mapped one, which can be expended */
	cur = bmgr->last_mapped_block;
	if (cur == &bmgr->blkh)
		cur = list_next_entry(cur, list);
	for (; cur != &bmgr->blkh; cur = list_next_entry(cur, list)) {
		used_before = cur->buffers.off & (blksiz - 1);

		/* skip if buffer block is just full */
		if (!used_before)
			continue;

		/* skip if the entry which has different type */
		if (cur->type != type)
			continue;

		ret = __erofs_battach(cur, NULL, size, alignsize,
				      inline_ext, true);
		if (ret < 0)
			continue;

		used = ret + inline_ext;
		DBG_BUGON(used > blksiz);

		/*
		 * remaining should be smaller than before or
		 * larger than allocating a new buffer block
		 */
		if (used < used_before && used < used0)
			continue;

		if (usedmax < used) {
			bb = cur;
			usedmax = used;
		}
	}
	*bbp = bb;
	return 0;
}

struct erofs_buffer_head *erofs_balloc(struct erofs_bufmgr *bmgr,
				       int type, erofs_off_t size,
				       unsigned int inline_ext)
{
	struct erofs_buffer_block *bb;
	struct erofs_buffer_head *bh;
	unsigned int alignsize;
	int ret;

	ret = get_alignsize(bmgr->sbi, type, &type);
	if (ret < 0)
		return ERR_PTR(ret);

	DBG_BUGON(type < 0 || type > META);
	alignsize = ret;

	/* try to find if we could reuse an allocated buffer block */
	ret = erofs_bfind_for_attach(bmgr, type, size, inline_ext,
				     alignsize, &bb);
	if (ret)
		return ERR_PTR(ret);

	if (bb) {
		bh = malloc(sizeof(struct erofs_buffer_head));
		if (!bh)
			return ERR_PTR(-ENOMEM);
	} else {
		/* get a new buffer block instead */
		bb = malloc(sizeof(struct erofs_buffer_block));
		if (!bb)
			return ERR_PTR(-ENOMEM);

		bb->type = type;
		bb->blkaddr = EROFS_NULL_ADDR;
		bb->buffers.off = 0;
		bb->buffers.nblocks = 0;
		bb->buffers.fsprivate = bmgr;
		init_list_head(&bb->buffers.list);
		if (type == DATA)
			list_add(&bb->list,
				 &bmgr->last_mapped_block->list);
		else
			list_add_tail(&bb->list, &bmgr->blkh.list);
		init_list_head(&bb->mapped_list);

		bh = malloc(sizeof(struct erofs_buffer_head));
		if (!bh) {
			free(bb);
			return ERR_PTR(-ENOMEM);
		}
	}

	ret = __erofs_battach(bb, bh, size, alignsize, inline_ext, false);
	if (ret < 0) {
		free(bh);
		return ERR_PTR(ret);
	}
	return bh;
}

struct erofs_buffer_head *erofs_battach(struct erofs_buffer_head *bh,
					int type, unsigned int size)
{
	struct erofs_buffer_block *const bb = bh->block;
	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
	struct erofs_buffer_head *nbh;
	unsigned int alignsize;
	int ret = get_alignsize(bmgr->sbi, type, &type);

	if (ret < 0)
		return ERR_PTR(ret);
	alignsize = ret;

	/* should be the tail bh in the corresponding buffer block */
	if (bh->list.next != &bb->buffers.list)
		return ERR_PTR(-EINVAL);

	nbh = malloc(sizeof(*nbh));
	if (!nbh)
		return ERR_PTR(-ENOMEM);

	ret = __erofs_battach(bb, nbh, size, alignsize, 0, false);
	if (ret < 0) {
		free(nbh);
		return ERR_PTR(ret);
	}
	return nbh;
}

static void __erofs_mapbh(struct erofs_buffer_block *bb)
{
	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
	erofs_blk_t blkaddr;

	if (bb->blkaddr == EROFS_NULL_ADDR) {
		bb->blkaddr = bmgr->tail_blkaddr;
		bmgr->last_mapped_block = bb;
		erofs_bupdate_mapped(bb);
	}

	blkaddr = bb->blkaddr + bb->buffers.nblocks;
	if (blkaddr > bmgr->tail_blkaddr)
		bmgr->tail_blkaddr = blkaddr;
}

erofs_blk_t erofs_mapbh(struct erofs_bufmgr *bmgr,
			struct erofs_buffer_block *bb)
{
	struct erofs_buffer_block *t;

	if (!bmgr)
		bmgr = bb->buffers.fsprivate;
	t = bmgr->last_mapped_block;

	if (bb && bb->blkaddr != EROFS_NULL_ADDR)
		return bb->blkaddr;
	do {
		t = list_next_entry(t, list);
		if (t == &bmgr->blkh)
			break;

		DBG_BUGON(t->blkaddr != EROFS_NULL_ADDR);
		__erofs_mapbh(t);
	} while (t != bb);
	return bmgr->tail_blkaddr;
}

static void erofs_bfree(struct erofs_buffer_block *bb)
{
	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;

	DBG_BUGON(!list_empty(&bb->buffers.list));

	if (bb == bmgr->last_mapped_block)
		bmgr->last_mapped_block = list_prev_entry(bb, list);

	list_del(&bb->mapped_list);
	list_del(&bb->list);
	free(bb);
}

int erofs_bflush(struct erofs_bufmgr *bmgr,
		 struct erofs_buffer_block *bb)
{
	struct erofs_sb_info *sbi = bmgr->sbi;
	const unsigned int blksiz = erofs_blksiz(sbi);
	struct erofs_buffer_block *p, *n;
	erofs_blk_t blkaddr;

	list_for_each_entry_safe(p, n, &bmgr->blkh.list, list) {
		struct erofs_buffer_head *bh, *nbh;
		unsigned int padding;
		bool skip = false;
		int ret;

		if (p == bb)
			break;

		__erofs_mapbh(p);
		blkaddr = p->blkaddr + BLK_ROUND_UP(sbi, p->buffers.off);

		list_for_each_entry_safe(bh, nbh, &p->buffers.list, list) {
			if (bh->op == &erofs_skip_write_bhops) {
				skip = true;
				continue;
			}

			/* flush and remove bh */
			ret = bh->op->flush(bh);
			if (ret < 0)
				return ret;
		}

		if (skip)
			continue;

		padding = blksiz - (p->buffers.off & (blksiz - 1));
		if (padding != blksiz)
			erofs_dev_fillzero(sbi, erofs_pos(sbi, blkaddr) - padding,
					   padding, true);

		if (p->type != DATA)
			bmgr->metablkcnt += p->buffers.nblocks;
		erofs_dbg("block %llu to %llu flushed", p->blkaddr | 0ULL,
			  (blkaddr - 1) | 0ULL);
		erofs_bfree(p);
	}
	return 0;
}

void erofs_bdrop(struct erofs_buffer_head *bh, bool tryrevoke)
{
	struct erofs_buffer_block *const bb = bh->block;
	struct erofs_bufmgr *bmgr = bb->buffers.fsprivate;
	const erofs_blk_t blkaddr = bh->block->blkaddr;
	bool rollback = false;

	/* tail_blkaddr could be rolled back after revoking all bhs */
	if (tryrevoke && blkaddr != EROFS_NULL_ADDR &&
	    bmgr->tail_blkaddr == blkaddr + bb->buffers.nblocks)
		rollback = true;

	bh->op = &erofs_drop_directly_bhops;
	erofs_bh_flush_generic_end(bh);

	if (!list_empty(&bb->buffers.list))
		return;

	if (!rollback && bb->type != DATA)
		bmgr->metablkcnt += bb->buffers.nblocks;
	erofs_bfree(bb);
	if (rollback)
		bmgr->tail_blkaddr = blkaddr;
}

erofs_blk_t erofs_total_metablocks(struct erofs_bufmgr *bmgr)
{
	return bmgr->metablkcnt;
}

void erofs_buffer_exit(struct erofs_bufmgr *bmgr)
{
	free(bmgr);
}
