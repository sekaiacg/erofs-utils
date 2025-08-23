// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * erofs-utils/lib/blobchunk.c
 *
 * Copyright (C) 2021, Alibaba Cloud
 */
#define _GNU_SOURCE
#include "erofs/hashmap.h"
#include "erofs/blobchunk.h"
#include "erofs/block_list.h"
#include "liberofs_cache.h"
#include "liberofs_private.h"
#include "sha256.h"
#include <unistd.h>

struct erofs_blobchunk {
	union {
		struct hashmap_entry ent;
		struct list_head list;
	};
	char		sha256[32];
	unsigned int	device_id;
	union {
		erofs_off_t	chunksize;
		erofs_off_t	sourceoffset;
	};
	erofs_blk_t	blkaddr;
};

static struct hashmap blob_hashmap;
static int blobfile = -1;
static erofs_blk_t remapped_base;
static erofs_off_t datablob_size;
struct erofs_blobchunk erofs_holechunk = {
	.blkaddr = EROFS_NULL_ADDR,
};
static LIST_HEAD(unhashed_blobchunks);

struct erofs_blobchunk *erofs_get_unhashed_chunk(unsigned int device_id,
		erofs_blk_t blkaddr, erofs_off_t sourceoffset)
{
	struct erofs_blobchunk *chunk;

	chunk = calloc(1, sizeof(struct erofs_blobchunk));
	if (!chunk)
		return ERR_PTR(-ENOMEM);

	chunk->device_id = device_id;
	chunk->blkaddr = blkaddr;
	chunk->sourceoffset = sourceoffset;
	list_add_tail(&chunk->list, &unhashed_blobchunks);
	return chunk;
}

static struct erofs_blobchunk *erofs_blob_getchunk(struct erofs_sb_info *sbi,
						u8 *buf, erofs_off_t chunksize)
{
	static u8 zeroed[EROFS_MAX_BLOCK_SIZE];
	struct erofs_blobchunk *chunk;
	unsigned int hash, padding;
	u8 sha256[32];
	erofs_off_t blkpos;
	int ret;

	erofs_sha256(buf, chunksize, sha256);
	hash = memhash(sha256, sizeof(sha256));
	chunk = hashmap_get_from_hash(&blob_hashmap, hash, sha256);
	if (chunk) {
		DBG_BUGON(chunksize != chunk->chunksize);

		sbi->saved_by_deduplication += chunksize;
		if (chunk->blkaddr == erofs_holechunk.blkaddr) {
			chunk = &erofs_holechunk;
			erofs_dbg("Found duplicated hole chunk");
		} else {
			erofs_dbg("Found duplicated chunk at %llu",
				  chunk->blkaddr | 0ULL);
		}
		return chunk;
	}

	chunk = malloc(sizeof(struct erofs_blobchunk));
	if (!chunk)
		return ERR_PTR(-ENOMEM);

	chunk->chunksize = chunksize;
	memcpy(chunk->sha256, sha256, sizeof(sha256));
	blkpos = lseek(blobfile, 0, SEEK_CUR);
	DBG_BUGON(erofs_blkoff(sbi, blkpos));

	if (sbi->extra_devices)
		chunk->device_id = 1;
	else
		chunk->device_id = 0;
	chunk->blkaddr = erofs_blknr(sbi, blkpos);

	erofs_dbg("Writing chunk (%llu bytes) to %llu", chunksize | 0ULL,
		  chunk->blkaddr | 0ULL);
	ret = __erofs_io_write(blobfile, buf, chunksize);
	if (ret == chunksize) {
		padding = erofs_blkoff(sbi, chunksize);
		if (padding) {
			padding = erofs_blksiz(sbi) - padding;
			ret = __erofs_io_write(blobfile, zeroed, padding);
			if (ret > 0 && ret != padding)
				ret = -EIO;
		}
	} else if (ret >= 0) {
		ret = -EIO;
	}

	if (ret < 0) {
		free(chunk);
		return ERR_PTR(ret);
	}

	hashmap_entry_init(&chunk->ent, hash);
	hashmap_add(&blob_hashmap, chunk);
	return chunk;
}

static int erofs_blob_hashmap_cmp(const void *a, const void *b,
				  const void *key)
{
	const struct erofs_blobchunk *ec1 =
			container_of((struct hashmap_entry *)a,
				     struct erofs_blobchunk, ent);
	const struct erofs_blobchunk *ec2 =
			container_of((struct hashmap_entry *)b,
				     struct erofs_blobchunk, ent);

	return memcmp(ec1->sha256, key ? key : ec2->sha256,
		      sizeof(ec1->sha256));
}

int erofs_write_chunk_indexes(struct erofs_inode *inode, struct erofs_vfile *vf,
			      erofs_off_t off)
{
	struct erofs_sb_info *sbi = inode->sbi;
	erofs_blk_t remaining_blks = BLK_ROUND_UP(sbi, inode->i_size);
	struct erofs_inode_chunk_index idx = {0};
	erofs_blk_t extent_end = EROFS_NULL_ADDR, chunkblks, addrmask;
	erofs_blk_t extent_start = EROFS_NULL_ADDR;
	erofs_off_t source_offset;
	unsigned int dst, src, unit, zeroedlen;
	bool _48bit;

	if (inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(struct erofs_inode_chunk_index);
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;

	chunkblks = 1ULL << (inode->u.chunkformat & EROFS_CHUNK_FORMAT_BLKBITS_MASK);
	_48bit = inode->u.chunkformat & EROFS_CHUNK_FORMAT_48BIT;
	for (dst = src = 0; dst < inode->extent_isize;
	     src += sizeof(void *), dst += unit) {
		struct erofs_blobchunk *chunk;
		erofs_blk_t startblk;

		chunk = *(void **)(inode->chunkindexes + src);

		if (chunk->blkaddr == EROFS_NULL_ADDR) {
			startblk = EROFS_NULL_ADDR;
		} else if (chunk->device_id) {
			DBG_BUGON(!(inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES));
			startblk = chunk->blkaddr;
			extent_start = EROFS_NULL_ADDR;
		} else {
			startblk = remapped_base + chunk->blkaddr;
		}

		if (extent_start == EROFS_NULL_ADDR || startblk != extent_end) {
			if (extent_start != EROFS_NULL_ADDR) {
				remaining_blks -= extent_end - extent_start;
				tarerofs_blocklist_write(extent_start,
						extent_end - extent_start,
						source_offset, 0);
			}
			extent_start = startblk;
			source_offset = chunk->sourceoffset;
		}
		extent_end = startblk + chunkblks;

		addrmask = _48bit ? BIT_ULL(48) - 1 : BIT_ULL(32) - 1;
		startblk &= addrmask;
		idx.device_id = cpu_to_le16(chunk->device_id);
		idx.startblk_lo = cpu_to_le32(startblk);
		idx.startblk_hi = cpu_to_le32(startblk >> 32);
		DBG_BUGON(!_48bit && idx.startblk_hi);

		if (unit == EROFS_BLOCK_MAP_ENTRY_SIZE)
			memcpy(inode->chunkindexes + dst, &idx.startblk_lo, unit);
		else
			memcpy(inode->chunkindexes + dst, &idx, sizeof(idx));
	}
	if (extent_start != EROFS_NULL_ADDR) {
		extent_end = min(extent_end, extent_start + remaining_blks);
		zeroedlen = inode->i_size & (erofs_blksiz(sbi) - 1);
		if (zeroedlen)
			zeroedlen = erofs_blksiz(sbi) - zeroedlen;
		tarerofs_blocklist_write(extent_start, extent_end - extent_start,
					 source_offset, zeroedlen);
	}
	off = roundup(off, unit);
	return erofs_io_pwrite(vf, inode->chunkindexes,
			       off, inode->extent_isize);
}

int erofs_blob_mergechunks(struct erofs_inode *inode, unsigned int chunkbits,
			   unsigned int new_chunkbits)
{
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int dst, src, unit, count;

	if (new_chunkbits - sbi->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
		new_chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi->blkszbits;
	if (chunkbits >= new_chunkbits)		/* no need to merge */
		goto out;

	if (inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(struct erofs_inode_chunk_index);
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;

	count = round_up(inode->i_size, 1ULL << new_chunkbits) >> new_chunkbits;
	for (dst = src = 0; dst < count; ++dst) {
		*((void **)inode->chunkindexes + dst) =
			*((void **)inode->chunkindexes + src);
		src += 1U << (new_chunkbits - chunkbits);
	}

	DBG_BUGON(count * unit >= inode->extent_isize);
	inode->extent_isize = count * unit;
	chunkbits = new_chunkbits;
out:
	inode->u.chunkformat = (chunkbits - sbi->blkszbits) |
		(inode->u.chunkformat & ~EROFS_CHUNK_FORMAT_BLKBITS_MASK);
	return 0;
}

static void erofs_update_minextblks(struct erofs_sb_info *sbi,
		    erofs_off_t start, erofs_off_t end, erofs_blk_t *minextblks)
{
	erofs_blk_t lb;
	lb = lowbit((end - start) >> sbi->blkszbits);
	if (lb && lb < *minextblks)
		*minextblks = lb;
}
static bool erofs_blob_can_merge(struct erofs_sb_info *sbi,
				 struct erofs_blobchunk *lastch,
				 struct erofs_blobchunk *chunk)
{
	if (!lastch)
		return true;
	if (lastch == &erofs_holechunk && chunk == &erofs_holechunk)
		return true;
	if (lastch->device_id == chunk->device_id &&
		erofs_pos(sbi, lastch->blkaddr) + lastch->chunksize ==
		erofs_pos(sbi, chunk->blkaddr))
		return true;

	return false;
}
int erofs_blob_write_chunked_file(struct erofs_inode *inode, int fd,
				  erofs_off_t startoff)
{
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int chunkbits = cfg.c_chunkbits;
	unsigned int count, unit;
	struct erofs_blobchunk *chunk, *lastch;
	struct erofs_inode_chunk_index *idx;
	erofs_off_t pos, len, chunksize, interval_start;
	erofs_blk_t minextblks;
	u8 *chunkdata;
	int ret;

#ifdef SEEK_DATA
	/* if the file is fully sparsed, use one big chunk instead */
	if (lseek(fd, startoff, SEEK_DATA) < 0 && errno == ENXIO) {
		chunkbits = ilog2(inode->i_size - 1) + 1;
		if (chunkbits < sbi->blkszbits)
			chunkbits = sbi->blkszbits;
	}
#endif
	if (chunkbits - sbi->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
		chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi->blkszbits;
	chunksize = 1ULL << chunkbits;
	count = DIV_ROUND_UP(inode->i_size, chunksize);

	if (sbi->extra_devices)
		inode->u.chunkformat |= EROFS_CHUNK_FORMAT_INDEXES;
	if (inode->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(struct erofs_inode_chunk_index);
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;

	chunkdata = malloc(chunksize);
	if (!chunkdata)
		return -ENOMEM;

	inode->extent_isize = count * unit;
	inode->chunkindexes = malloc(count * max(sizeof(*idx), sizeof(void *)));
	if (!inode->chunkindexes) {
		ret = -ENOMEM;
		goto err;
	}
	idx = inode->chunkindexes;
	lastch = NULL;
	minextblks = BLK_ROUND_UP(sbi, inode->i_size);
	interval_start = 0;

	/*
	 * If dsunit <= chunksize, deduplication will not cause misalignment,
	 * so it's uncontroversial to apply the current data alignment policy.
	 */
	if (sbi->bmgr->dsunit > 1 &&
	    sbi->bmgr->dsunit <= (1u << (chunkbits - sbi->blkszbits))) {
		off_t off = lseek(blobfile, 0, SEEK_CUR);

		off = roundup(off, sbi->bmgr->dsunit * erofs_blksiz(sbi));
		if (lseek(blobfile, off, SEEK_SET) != off) {
			ret = -errno;
			erofs_err("failed to lseek blobdev@0x%llx: %s", off,
				  erofs_strerror(ret));
			goto err;
		}
		erofs_dbg("Align /%s on block #%d (0x%llx)",
			  erofs_fspath(inode->i_srcpath), erofs_blknr(sbi, off), off);
	}

	for (pos = 0; pos < inode->i_size; pos += len) {
#ifdef SEEK_DATA
		off_t offset = lseek(fd, pos + startoff, SEEK_DATA);

		if (offset < 0) {
			if (errno != ENXIO)
				offset = pos;
			else
				offset = ((pos >> chunkbits) + 1) << chunkbits;
		} else {
			offset -= startoff;

			if (offset != (offset & ~(chunksize - 1))) {
				offset &= ~(chunksize - 1);
				if (lseek(fd, offset + startoff, SEEK_SET) !=
					  startoff + offset) {
					ret = -EIO;
					goto err;
				}
			}
		}

		if (offset > pos) {
			if (!erofs_blob_can_merge(sbi, lastch,
							&erofs_holechunk)) {
				erofs_update_minextblks(sbi, interval_start,
							pos, &minextblks);
				interval_start = pos;
			}
			do {
				*(void **)idx++ = &erofs_holechunk;
				pos += chunksize;
			} while (pos < offset);
			DBG_BUGON(pos != offset);
			lastch = &erofs_holechunk;
			len = 0;
			continue;
		}
#endif

		len = min_t(u64, inode->i_size - pos, chunksize);
		ret = read(fd, chunkdata, len);
		if (ret < len) {
			ret = -EIO;
			goto err;
		}

		chunk = erofs_blob_getchunk(sbi, chunkdata, len);
		if (IS_ERR(chunk)) {
			ret = PTR_ERR(chunk);
			goto err;
		}

		/* FIXME! `chunk->blkaddr` is not the final blkaddr here */
		if (chunk->blkaddr != EROFS_NULL_ADDR &&
		    chunk->blkaddr >= UINT32_MAX)
			inode->u.chunkformat |= EROFS_CHUNK_FORMAT_48BIT;
		if (!erofs_blob_can_merge(sbi, lastch, chunk)) {
			erofs_update_minextblks(sbi, interval_start, pos,
						&minextblks);
			interval_start = pos;
		}
		*(void **)idx++ = chunk;
		lastch = chunk;
	}
	erofs_update_minextblks(sbi, interval_start, pos, &minextblks);
	inode->datalayout = EROFS_INODE_CHUNK_BASED;
	free(chunkdata);
	return erofs_blob_mergechunks(inode, chunkbits,
				      ilog2(minextblks) + sbi->blkszbits);
err:
	free(inode->chunkindexes);
	inode->chunkindexes = NULL;
	free(chunkdata);
	return ret;
}

int erofs_write_zero_inode(struct erofs_inode *inode)
{
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int chunkbits = ilog2(inode->i_size - 1) + 1;
	unsigned int count;
	erofs_off_t chunksize, len, pos;
	struct erofs_inode_chunk_index *idx;

	if (chunkbits < sbi->blkszbits)
		chunkbits = sbi->blkszbits;
	if (chunkbits - sbi->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
		chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi->blkszbits;

	inode->u.chunkformat |= chunkbits - sbi->blkszbits;

	chunksize = 1ULL << chunkbits;
	count = DIV_ROUND_UP(inode->i_size, chunksize);

	inode->extent_isize = count * EROFS_BLOCK_MAP_ENTRY_SIZE;
	idx = calloc(count, max(sizeof(*idx), sizeof(void *)));
	if (!idx)
		return -ENOMEM;
	inode->chunkindexes = idx;

	for (pos = 0; pos < inode->i_size; pos += len) {
		struct erofs_blobchunk *chunk;

		len = min_t(erofs_off_t, inode->i_size - pos, chunksize);
		chunk = erofs_get_unhashed_chunk(0, EROFS_NULL_ADDR, -1);
		if (IS_ERR(chunk)) {
			free(inode->chunkindexes);
			inode->chunkindexes = NULL;
			return PTR_ERR(chunk);
		}

		*(void **)idx++ = chunk;
	}
	inode->datalayout = EROFS_INODE_CHUNK_BASED;
	return 0;
}

int tarerofs_write_chunkes(struct erofs_inode *inode, erofs_off_t data_offset)
{
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int chunkbits = ilog2(inode->i_size - 1) + 1;
	unsigned int count, unit, device_id;
	erofs_off_t chunksize, len, pos;
	erofs_blk_t blkaddr;
	struct erofs_inode_chunk_index *idx;

	if (chunkbits < sbi->blkszbits)
		chunkbits = sbi->blkszbits;
	if (chunkbits - sbi->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
		chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + sbi->blkszbits;

	inode->u.chunkformat |= chunkbits - sbi->blkszbits;
	if (sbi->extra_devices) {
		device_id = 1;
		inode->u.chunkformat |= EROFS_CHUNK_FORMAT_INDEXES;
		unit = sizeof(struct erofs_inode_chunk_index);
		DBG_BUGON(erofs_blkoff(sbi, data_offset));
		blkaddr = erofs_blknr(sbi, data_offset);
	} else {
		device_id = 0;
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;
		DBG_BUGON(erofs_blkoff(sbi, datablob_size));
		blkaddr = erofs_blknr(sbi, datablob_size);
		datablob_size += round_up(inode->i_size, erofs_blksiz(sbi));
	}
	chunksize = 1ULL << chunkbits;
	count = DIV_ROUND_UP(inode->i_size, chunksize);

	inode->extent_isize = count * unit;
	idx = calloc(count, max(sizeof(*idx), sizeof(void *)));
	if (!idx)
		return -ENOMEM;
	inode->chunkindexes = idx;

	for (pos = 0; pos < inode->i_size; pos += len) {
		struct erofs_blobchunk *chunk;

		len = min_t(erofs_off_t, inode->i_size - pos, chunksize);

		chunk = erofs_get_unhashed_chunk(device_id, blkaddr,
						 data_offset);
		if (IS_ERR(chunk)) {
			free(inode->chunkindexes);
			inode->chunkindexes = NULL;
			return PTR_ERR(chunk);
		}

		*(void **)idx++ = chunk;
		blkaddr += erofs_blknr(sbi, len);
		data_offset += len;
	}
	inode->datalayout = EROFS_INODE_CHUNK_BASED;
	return 0;
}

int erofs_mkfs_dump_blobs(struct erofs_sb_info *sbi)
{
	struct erofs_buffer_head *bh;
	ssize_t length, ret;
	u64 pos_in, pos_out;

	if (blobfile >= 0) {
		length = lseek(blobfile, 0, SEEK_CUR);
		if (length < 0)
			return -errno;

		if (sbi->extra_devices)
			sbi->devs[0].blocks = erofs_blknr(sbi, length);
		else
			datablob_size = length;
	}

	if (sbi->extra_devices)
		return 0;

	bh = erofs_balloc(sbi->bmgr, DATA, datablob_size, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);

	erofs_mapbh(NULL, bh->block);

	pos_out = erofs_btell(bh, false);
	remapped_base = erofs_blknr(sbi, pos_out);
	pos_out += sbi->bdev.offset;
	if (blobfile >= 0) {
		pos_in = 0;
		do {
			length = min_t(erofs_off_t, datablob_size,  SSIZE_MAX);
			ret = erofs_copy_file_range(blobfile, &pos_in,
					sbi->bdev.fd, &pos_out, length);
		} while (ret > 0 && (datablob_size -= ret));

		if (ret >= 0) {
			if (datablob_size) {
				erofs_err("failed to append the remaining %llu-byte chunk data",
					  datablob_size);
				ret = -EIO;
			} else {
				ret = 0;
			}
		}
	} else {
		ret = erofs_io_ftruncate(&sbi->bdev, pos_out + datablob_size);
	}
	bh->op = &erofs_drop_directly_bhops;
	erofs_bdrop(bh, false);
	return ret;
}

void erofs_blob_exit(void)
{
	struct hashmap_iter iter;
	struct hashmap_entry *e;
	struct erofs_blobchunk *bc, *n;

	if (blobfile >= 0)
		close(blobfile);

	/* Disable hashmap shrink, effectively disabling rehash.
	 * This way we can iterate over entire hashmap efficiently
	 * and safely by using hashmap_iter_next() */
	hashmap_disable_shrink(&blob_hashmap);
	e = hashmap_iter_first(&blob_hashmap, &iter);
	while (e) {
		bc = container_of((struct hashmap_entry *)e,
				  struct erofs_blobchunk, ent);
		DBG_BUGON(hashmap_remove(&blob_hashmap, e) != e);
		free(bc);
		e = hashmap_iter_next(&iter);
	}
	DBG_BUGON(hashmap_free(&blob_hashmap));

	list_for_each_entry_safe(bc, n, &unhashed_blobchunks, list) {
		list_del(&bc->list);
		free(bc);
	}
}

static int erofs_insert_zerochunk(erofs_off_t chunksize)
{
	u8 *zeros;
	struct erofs_blobchunk *chunk;
	u8 sha256[32];
	unsigned int hash;
	int ret = 0;

	zeros = calloc(1, chunksize);
	if (!zeros)
		return -ENOMEM;

	erofs_sha256(zeros, chunksize, sha256);
	free(zeros);
	hash = memhash(sha256, sizeof(sha256));
	chunk = malloc(sizeof(struct erofs_blobchunk));
	if (!chunk)
		return -ENOMEM;

	chunk->chunksize = chunksize;
	/* treat chunk filled with zeros as hole */
	chunk->blkaddr = erofs_holechunk.blkaddr;
	memcpy(chunk->sha256, sha256, sizeof(sha256));

	hashmap_entry_init(&chunk->ent, hash);
	hashmap_add(&blob_hashmap, chunk);
	return ret;
}

int erofs_blob_init(const char *blobfile_path, erofs_off_t chunksize)
{
	if (!blobfile_path)
		blobfile = erofs_tmpfile();
	else
		blobfile = open(blobfile_path, O_WRONLY | O_CREAT |
						O_TRUNC | O_BINARY, 0666);
	if (blobfile < 0)
		return -errno;

	hashmap_init(&blob_hashmap, erofs_blob_hashmap_cmp, 0);
	return erofs_insert_zerochunk(chunksize);
}
