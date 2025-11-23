// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2020 Gao Xiang <hsiangkao@aol.com>
 * Compression support by Huang Jianan <huangjianan@oppo.com>
 */
#include <stdlib.h>
#include "erofs/print.h"
#include "erofs/internal.h"
#include "erofs/trace.h"
#include "erofs/decompress.h"
#include "liberofs_fragments.h"

void *erofs_bread(struct erofs_buf *buf, erofs_off_t offset, bool need_kmap)
{
	struct erofs_sb_info *sbi = buf->sbi;
	u32 blksiz = erofs_blksiz(sbi);
	struct erofs_vfile vfm, *vf;
	struct erofs_inode vi;
	erofs_blk_t blknr;
	int err;

	if (!need_kmap)
		return NULL;
	blknr = erofs_blknr(sbi, offset);
	if (blknr != buf->blocknr) {
		buf->blocknr = ~0ULL;
		vf = buf->vf;
		/*
		 * TODO: introduce a metabox cache like the current fragment
		 *       cache to improve userspace metadata performance.
		 */
		if (!vf) {
			if (!erofs_sb_has_metabox(sbi))
				return ERR_PTR(-EFSCORRUPTED);

			vi = (struct erofs_inode) { .sbi = sbi,
						    .nid = sbi->metabox_nid };
			err = erofs_read_inode_from_disk(&vi);
			if (!err)
				err = erofs_iopen(&vfm, &vi);
			if (err)
				return ERR_PTR(err);
			vf = &vfm;
		}
		err = erofs_pread(vf, buf->base, blksiz,
				  round_down(offset, blksiz));
		if (err)
			return ERR_PTR(err);
		buf->blocknr = blknr;
	}
	return buf->base + erofs_blkoff(sbi, offset);
}

void erofs_init_metabuf(struct erofs_buf *buf, struct erofs_sb_info *sbi,
			bool in_mbox)
{
	buf->sbi = sbi;
	buf->vf = in_mbox ? NULL : &sbi->bdev;
}

void *erofs_read_metabuf(struct erofs_buf *buf, struct erofs_sb_info *sbi,
			 erofs_off_t offset, bool in_mbox)
{
	erofs_init_metabuf(buf, sbi, in_mbox);
	return erofs_bread(buf, offset, true);
}

int __erofs_map_blocks(struct erofs_inode *inode,
		       struct erofs_map_blocks *map, int flags)
{
	struct erofs_inode *vi = inode;
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int unit, blksz = 1 << sbi->blkszbits;
	struct erofs_inode_chunk_index *idx;
	u8 buf[EROFS_MAX_BLOCK_SIZE];
	erofs_blk_t startblk, addrmask, nblocks;
	bool tailpacking;
	erofs_off_t pos;
	u64 chunknr;
	int err = 0;

	map->m_deviceid = 0;
	map->m_flags = 0;
	if (map->m_la >= inode->i_size)
		goto out;

	if (vi->datalayout != EROFS_INODE_CHUNK_BASED) {
		tailpacking = (vi->datalayout == EROFS_INODE_FLAT_INLINE);
		if (!tailpacking && vi->u.i_blkaddr == EROFS_NULL_ADDR) {
			map->m_llen = inode->i_size - map->m_la;
			goto out;
		}
		nblocks = BLK_ROUND_UP(sbi, inode->i_size);
		pos = erofs_pos(sbi, nblocks - tailpacking);

		map->m_flags = EROFS_MAP_MAPPED;
		if (map->m_la < pos) {
			map->m_pa = erofs_pos(sbi, vi->u.i_blkaddr) + map->m_la;
			map->m_llen = pos - map->m_la;
		} else {
			map->m_pa = erofs_iloc(inode) + vi->inode_isize +
				vi->xattr_isize + erofs_blkoff(sbi, map->m_la);
			map->m_llen = inode->i_size - map->m_la;
			map->m_flags |= EROFS_MAP_META;
		}
		goto out;
	}

	if (vi->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(*idx);			/* chunk index */
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;	/* block map */

	chunknr = map->m_la >> vi->u.chunkbits;
	pos = roundup(erofs_iloc(vi) + vi->inode_isize +
		      vi->xattr_isize, unit) + unit * chunknr;

	err = erofs_blk_read(sbi, 0, buf, erofs_blknr(sbi, pos), 1);
	if (err < 0)
		return -EIO;

	idx = (void *)buf + erofs_blkoff(sbi, pos);
	map->m_la = chunknr << vi->u.chunkbits;
	map->m_llen = min_t(erofs_off_t, 1ULL << vi->u.chunkbits,
			    round_up(inode->i_size - map->m_la, blksz));
	if (vi->u.chunkformat & EROFS_CHUNK_FORMAT_INDEXES) {
		addrmask = (vi->u.chunkformat & EROFS_CHUNK_FORMAT_48BIT) ?
			BIT_ULL(48) - 1 : BIT_ULL(32) - 1;
		startblk = (((u64)le16_to_cpu(idx->startblk_hi) << 32) |
			le32_to_cpu(idx->startblk_lo)) & addrmask;
		if ((startblk ^ EROFS_NULL_ADDR) & addrmask) {
			map->m_deviceid = le16_to_cpu(idx->device_id) &
				sbi->device_id_mask;
			map->m_pa = erofs_pos(sbi, startblk);
			map->m_flags = EROFS_MAP_MAPPED;
		}
	} else {
		startblk = le32_to_cpu(*(__le32 *)idx);
		if (startblk != EROFS_NULL_ADDR) {
			map->m_pa = erofs_pos(sbi, startblk);
			map->m_flags = EROFS_MAP_MAPPED;
		}
	}
out:
	if (!err) {
		map->m_plen = map->m_llen;
		/* inline data should be located in the same meta block */
		if ((map->m_flags & EROFS_MAP_META) &&
		    erofs_blkoff(sbi, map->m_pa) + map->m_plen > blksz) {
			erofs_err("inline data across blocks @ nid %llu", vi->nid);
			DBG_BUGON(1);
			return -EFSCORRUPTED;
		}
	}
	return err;
}

int erofs_map_blocks(struct erofs_inode *inode,
		     struct erofs_map_blocks *map, int flags)
{
	if (erofs_inode_is_data_compressed(inode->datalayout))
		return z_erofs_map_blocks_iter(inode, map, flags);
	return __erofs_map_blocks(inode, map, flags);
}

int erofs_map_dev(struct erofs_sb_info *sbi, struct erofs_map_dev *map)
{
	struct erofs_device_info *dif;
	int id;

	if (map->m_deviceid) {
		if (sbi->extra_devices < map->m_deviceid)
			return -ENODEV;
	} else if (sbi->extra_devices) {
		for (id = 0; id < sbi->extra_devices; ++id) {
			erofs_off_t startoff, length;

			dif = sbi->devs + id;
			if (!dif->uniaddr)
				continue;
			startoff = erofs_pos(sbi, dif->uniaddr);
			length = erofs_pos(sbi, dif->blocks);

			if (map->m_pa >= startoff &&
			    map->m_pa < startoff + length) {
				map->m_pa -= startoff;
				break;
			}
		}
	}
	return 0;
}

int erofs_read_one_data(struct erofs_inode *inode, struct erofs_map_blocks *map,
			char *buffer, u64 offset, size_t len)
{
	struct erofs_sb_info *sbi = inode->sbi;
	struct erofs_map_dev mdev;
	int ret;

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map->m_deviceid,
		.m_pa = map->m_pa,
	};
	ret = erofs_map_dev(sbi, &mdev);
	if (ret)
		return ret;

	ret = erofs_dev_read(sbi, mdev.m_deviceid, buffer, mdev.m_pa + offset, len);
	if (ret < 0)
		return -EIO;
	return 0;
}

static int erofs_read_raw_data(struct erofs_inode *inode, char *buffer,
			       erofs_off_t size, erofs_off_t offset)
{
	struct erofs_map_blocks map = {
		.buf = __EROFS_BUF_INITIALIZER,
	};
	int ret;
	erofs_off_t ptr = offset;

	while (ptr < offset + size) {
		char *const estart = buffer + ptr - offset;
		erofs_off_t eend, moff = 0;

		map.m_la = ptr;
		ret = erofs_map_blocks(inode, &map, 0);
		if (ret)
			return ret;

		DBG_BUGON(map.m_plen != map.m_llen);

		/* trim extent */
		eend = min(offset + size, map.m_la + map.m_llen);
		DBG_BUGON(ptr < map.m_la);

		if ((map.m_flags & EROFS_MAP_META) &&
		    erofs_inode_in_metabox(inode)) {
			struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
			void *src;

			src = erofs_read_metabuf(&buf, inode->sbi,
						 map.m_pa, true);
			if (IS_ERR(src))
				return PTR_ERR(src);
			memcpy(estart, src, eend - ptr);
			erofs_put_metabuf(&buf);
			ptr = eend;
			continue;
		} else if (!(map.m_flags & EROFS_MAP_MAPPED)) {
			if (!map.m_llen) {
				/* reached EOF */
				memset(estart, 0, offset + size - ptr);
				ptr = offset + size;
				continue;
			}
			memset(estart, 0, eend - ptr);
			ptr = eend;
			continue;
		}

		if (ptr > map.m_la) {
			moff = ptr - map.m_la;
			map.m_la = ptr;
		}

		ret = erofs_read_one_data(inode, &map, estart, moff,
					  eend - map.m_la);
		if (ret)
			return ret;
		ptr = eend;
	}
	return 0;
}

int z_erofs_read_one_data(struct erofs_inode *inode,
			struct erofs_map_blocks *map, char *raw, char *buffer,
			erofs_off_t skip, erofs_off_t length, bool trimmed)
{
	struct erofs_sb_info *sbi = inode->sbi;
	struct erofs_map_dev mdev;
	int ret = 0;

	if (map->m_flags & __EROFS_MAP_FRAGMENT) {
		if (__erofs_unlikely(inode->nid == sbi->packed_nid)) {
			erofs_err("fragment should not exist in the packed inode %llu",
				  sbi->packed_nid | 0ULL);
			return -EFSCORRUPTED;
		}
		return erofs_packedfile_read(sbi, buffer, length - skip,
				   inode->fragmentoff + skip);
	}

	/* no device id here, thus it will always succeed */
	mdev = (struct erofs_map_dev) {
		.m_pa = map->m_pa,
	};
	ret = erofs_map_dev(sbi, &mdev);
	if (ret) {
		DBG_BUGON(1);
		return ret;
	}

	ret = erofs_dev_read(sbi, mdev.m_deviceid, raw, mdev.m_pa, map->m_plen);
	if (ret < 0)
		return ret;

	ret = z_erofs_decompress(&(struct z_erofs_decompress_req) {
			.sbi = sbi,
			.in = raw,
			.out = buffer,
			.decodedskip = skip,
			.interlaced_offset =
				map->m_algorithmformat == Z_EROFS_COMPRESSION_INTERLACED ?
					erofs_blkoff(sbi, map->m_la) : 0,
			.inputsize = map->m_plen,
			.decodedlength = length,
			.alg = map->m_algorithmformat,
			.partial_decoding = trimmed ? true :
				!(map->m_flags & EROFS_MAP_FULL_MAPPED) ||
					(map->m_flags & EROFS_MAP_PARTIAL_REF),
			 });
	if (ret < 0)
		return ret;
	return 0;
}

static int z_erofs_read_data(struct erofs_inode *inode, char *buffer,
			     erofs_off_t size, erofs_off_t offset)
{
	erofs_off_t end, length, skip;
	struct erofs_map_blocks map = {
		.buf = __EROFS_BUF_INITIALIZER,
	};
	bool trimmed;
	unsigned int bufsize = 0;
	char *raw = NULL;
	int ret = 0;

	end = offset + size;
	while (end > offset) {
		map.m_la = end - 1;

		ret = z_erofs_map_blocks_iter(inode, &map, 0);
		if (ret)
			break;

		/*
		 * trim to the needed size if the returned extent is quite
		 * larger than requested, and set up partial flag as well.
		 */
		if (end < map.m_la + map.m_llen) {
			length = end - map.m_la;
			trimmed = true;
		} else {
			DBG_BUGON(end != map.m_la + map.m_llen);
			length = map.m_llen;
			trimmed = false;
		}

		if (map.m_la < offset) {
			skip = offset - map.m_la;
			end = offset;
		} else {
			skip = 0;
			end = map.m_la;
		}

		if (!(map.m_flags & EROFS_MAP_MAPPED)) {
			memset(buffer + end - offset, 0, length - skip);
			end = map.m_la;
			continue;
		}

		if (map.m_plen > bufsize) {
			char *newraw;

			bufsize = map.m_plen;
			newraw = realloc(raw, bufsize);
			if (!newraw) {
				ret = -ENOMEM;
				break;
			}
			raw = newraw;
		}

		ret = z_erofs_read_one_data(inode, &map, raw,
				buffer + end - offset, skip, length, trimmed);
		if (ret < 0)
			break;
	}
	if (raw)
		free(raw);
	return ret < 0 ? ret : 0;
}

ssize_t erofs_preadi(struct erofs_vfile *vf, void *buf, size_t len, u64 offset)
{
	struct erofs_inode *inode = *(struct erofs_inode **)vf->payload;

	if (erofs_inode_is_data_compressed(inode->datalayout))
		return z_erofs_read_data(inode, buf, len, offset) ?: len;
	return erofs_read_raw_data(inode, buf, len, offset) ?: len;
}

int erofs_iopen(struct erofs_vfile *vf, struct erofs_inode *inode)
{
	static struct erofs_vfops ops = {
		.pread = erofs_preadi,
	};

	vf->ops = &ops;
	*(struct erofs_inode **)vf->payload = inode;
	return 0;
}

static void *erofs_read_metadata_nid(struct erofs_sb_info *sbi, erofs_nid_t nid,
				     erofs_off_t *offset, int *lengthp)
{
	struct erofs_inode vi = { .sbi = sbi, .nid = nid };
	struct erofs_vfile vf;
	__le16 __len;
	int ret, len;
	char *buffer;

	ret = erofs_read_inode_from_disk(&vi);
	if (ret)
		return ERR_PTR(ret);

	ret = erofs_iopen(&vf, &vi);
	if (ret)
		return ERR_PTR(ret);

	*offset = round_up(*offset, 4);
	ret = erofs_pread(&vf, (void *)&__len, sizeof(__le16), *offset);
	if (ret)
		return ERR_PTR(ret);

	len = le16_to_cpu(__len);
	if (!len)
		return ERR_PTR(-EFSCORRUPTED);

	buffer = malloc(len);
	if (!buffer)
		return ERR_PTR(-ENOMEM);
	*offset += sizeof(__le16);
	*lengthp = len;

	ret = erofs_pread(&vf, buffer, len, *offset);
	if (ret) {
		free(buffer);
		return ERR_PTR(ret);
	}
	*offset += len;
	return buffer;
}

static void *erofs_read_metadata_bdi(struct erofs_sb_info *sbi,
				     erofs_off_t *offset, int *lengthp)
{
	int ret, len, i, cnt;
	void *buffer;
	u8 data[EROFS_MAX_BLOCK_SIZE];

	*offset = round_up(*offset, 4);
	ret = erofs_blk_read(sbi, 0, data, erofs_blknr(sbi, *offset), 1);
	if (ret)
		return ERR_PTR(ret);
	len = le16_to_cpu(*(__le16 *)(data + erofs_blkoff(sbi, *offset)));
	if (!len)
		return ERR_PTR(-EFSCORRUPTED);

	buffer = malloc(len);
	if (!buffer)
		return ERR_PTR(-ENOMEM);
	*offset += sizeof(__le16);
	*lengthp = len;

	for (i = 0; i < len; i += cnt) {
		cnt = min_t(int, erofs_blksiz(sbi) - erofs_blkoff(sbi, *offset),
			    len - i);
		ret = erofs_blk_read(sbi, 0, data, erofs_blknr(sbi, *offset), 1);
		if (ret) {
			free(buffer);
			return ERR_PTR(ret);
		}
		memcpy(buffer + i, data + erofs_blkoff(sbi, *offset), cnt);
		*offset += cnt;
	}
	return buffer;
}

/*
 * read variable-sized metadata, offset will be aligned by 4-byte
 *
 * @nid is 0 if metadata is in meta inode
 */
void *erofs_read_metadata(struct erofs_sb_info *sbi, erofs_nid_t nid,
			  erofs_off_t *offset, int *lengthp)
{
	if (nid)
		return erofs_read_metadata_nid(sbi, nid, offset, lengthp);
	return erofs_read_metadata_bdi(sbi, offset, lengthp);
}
