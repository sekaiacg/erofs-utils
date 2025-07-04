// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 * with heavy changes by Gao Xiang <xiang@kernel.org>
 */
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <config.h>
#if defined(HAVE_SYS_SYSMACROS_H)
#include <sys/sysmacros.h>
#endif
#include <dirent.h>
#include "erofs/print.h"
#include "erofs/lock.h"
#include "erofs/diskbuf.h"
#include "erofs/inode.h"
#include "erofs/cache.h"
#include "erofs/compress.h"
#include "erofs/xattr.h"
#include "erofs/exclude.h"
#include "erofs/block_list.h"
#include "erofs/compress_hints.h"
#include "erofs/blobchunk.h"
#include "erofs/fragments.h"
#include "liberofs_private.h"

#define S_SHIFT                 12
static unsigned char erofs_ftype_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]  = EROFS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]  = EROFS_FT_DIR,
	[S_IFCHR >> S_SHIFT]  = EROFS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]  = EROFS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]  = EROFS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT] = EROFS_FT_SOCK,
	[S_IFLNK >> S_SHIFT]  = EROFS_FT_SYMLINK,
};

unsigned char erofs_mode_to_ftype(umode_t mode)
{
	return erofs_ftype_by_mode[(mode & S_IFMT) >> S_SHIFT];
}

static const unsigned char erofs_dtype_by_ftype[EROFS_FT_MAX] = {
	[EROFS_FT_UNKNOWN]	= DT_UNKNOWN,
	[EROFS_FT_REG_FILE]	= DT_REG,
	[EROFS_FT_DIR]		= DT_DIR,
	[EROFS_FT_CHRDEV]	= DT_CHR,
	[EROFS_FT_BLKDEV]	= DT_BLK,
	[EROFS_FT_FIFO]		= DT_FIFO,
	[EROFS_FT_SOCK]		= DT_SOCK,
	[EROFS_FT_SYMLINK]	= DT_LNK
};

static const umode_t erofs_dtype_by_umode[EROFS_FT_MAX] = {
	[EROFS_FT_UNKNOWN]	= S_IFMT,
	[EROFS_FT_REG_FILE]	= S_IFREG,
	[EROFS_FT_DIR]		= S_IFDIR,
	[EROFS_FT_CHRDEV]	= S_IFCHR,
	[EROFS_FT_BLKDEV]	= S_IFBLK,
	[EROFS_FT_FIFO]		= S_IFIFO,
	[EROFS_FT_SOCK]		= S_IFSOCK,
	[EROFS_FT_SYMLINK]	= S_IFLNK
};

umode_t erofs_ftype_to_mode(unsigned int ftype, unsigned int perm)
{
	if (ftype >= EROFS_FT_MAX)
		ftype = EROFS_FT_UNKNOWN;

	return erofs_dtype_by_umode[ftype] | perm;
}

unsigned char erofs_ftype_to_dtype(unsigned int filetype)
{
	if (filetype >= EROFS_FT_MAX)
		return DT_UNKNOWN;

	return erofs_dtype_by_ftype[filetype];
}

static struct list_head erofs_ihash[65536];
static erofs_rwsem_t erofs_ihashlock;

void erofs_inode_manager_init(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(erofs_ihash); ++i)
		init_list_head(&erofs_ihash[i]);
	erofs_init_rwsem(&erofs_ihashlock);
}

void erofs_insert_ihash(struct erofs_inode *inode)
{
	u32 nr = (inode->i_ino[1] ^ inode->dev) % ARRAY_SIZE(erofs_ihash);

	erofs_down_write(&erofs_ihashlock);
	list_add(&inode->i_hash, &erofs_ihash[nr]);
	erofs_up_write(&erofs_ihashlock);
}

void erofs_remove_ihash(struct erofs_inode *inode)
{
	erofs_down_write(&erofs_ihashlock);
	list_del(&inode->i_hash);
	erofs_up_write(&erofs_ihashlock);
}

/* get the inode from the (source) inode # */
struct erofs_inode *erofs_iget(dev_t dev, ino_t ino)
{
	u32 nr = (ino ^ dev) % ARRAY_SIZE(erofs_ihash);
	struct list_head *head = &erofs_ihash[nr];
	struct erofs_inode *ret = NULL, *inode;

	erofs_down_read(&erofs_ihashlock);
	list_for_each_entry(inode, head, i_hash) {
		if (inode->i_ino[1] == ino && inode->dev == dev) {
			ret = erofs_igrab(inode);
			break;
		}
	}
	erofs_up_read(&erofs_ihashlock);
	return ret;
}

unsigned int erofs_iput(struct erofs_inode *inode)
{
	struct erofs_dentry *d, *t;
	unsigned long got = erofs_atomic_dec_return(&inode->i_count);

	if (got >= 1)
		return got;

	list_for_each_entry_safe(d, t, &inode->i_subdirs, d_child)
		free(d);

	free(inode->compressmeta);
	free(inode->eof_tailraw);
	erofs_remove_ihash(inode);
	free(inode->i_srcpath);

	if (inode->datasource == EROFS_INODE_DATA_SOURCE_DISKBUF) {
		erofs_diskbuf_close(inode->i_diskbuf);
		free(inode->i_diskbuf);
	} else {
		free(inode->i_link);
	}
	free(inode);
	return 0;
}

struct erofs_dentry *erofs_d_alloc(struct erofs_inode *parent,
				   const char *name)
{
	unsigned int namelen = strlen(name);
	unsigned int fsz = round_up(namelen + 1, EROFS_DENTRY_NAME_ALIGNMENT);
	struct erofs_dentry *d;

	if (namelen > EROFS_NAME_LEN) {
		DBG_BUGON(1);
		return ERR_PTR(-ENAMETOOLONG);
	}
	d = malloc(sizeof(*d) + fsz);
	if (!d)
		return ERR_PTR(-ENOMEM);

	memcpy(d->name, name, namelen);
	memset(d->name + namelen, 0, fsz - namelen);
	d->inode = NULL;
	d->namelen = namelen;
	d->type = EROFS_FT_UNKNOWN;
	d->validnid = false;
	list_add_tail(&d->d_child, &parent->i_subdirs);
	return d;
}

/* allocate main data for an inode */
int erofs_allocate_inode_bh_data(struct erofs_inode *inode, erofs_blk_t nblocks)
{
	struct erofs_bufmgr *bmgr = inode->sbi->bmgr;
	struct erofs_buffer_head *bh;
	int ret, type;

	if (!nblocks) {
		/* it has only tail-end data */
		inode->u.i_blkaddr = EROFS_NULL_ADDR;
		return 0;
	}

	/* allocate main data buffer */
	type = S_ISDIR(inode->i_mode) ? DIRA : DATA;
	bh = erofs_balloc(bmgr, type, erofs_pos(inode->sbi, nblocks), 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);

	bh->op = &erofs_skip_write_bhops;
	inode->bh_data = bh;

	/* get blkaddr of the bh */
	ret = erofs_mapbh(NULL, bh->block);
	DBG_BUGON(ret < 0);

	/* write blocks except for the tail-end block */
	inode->u.i_blkaddr = bh->block->blkaddr;
	return 0;
}

static int comp_subdir(const void *a, const void *b)
{
	const struct erofs_dentry *da, *db;
	int commonlen, sign;

	da = *((const struct erofs_dentry **)a);
	db = *((const struct erofs_dentry **)b);
	commonlen = min(round_up(da->namelen, EROFS_DENTRY_NAME_ALIGNMENT),
			round_up(db->namelen, EROFS_DENTRY_NAME_ALIGNMENT));
	sign = memcmp(da->name, db->name, commonlen);
	if (sign)
		return sign;
	return cmpsgn(da->namelen, db->namelen);
}

int erofs_init_empty_dir(struct erofs_inode *dir)
{
	struct erofs_dentry *d;

	/* dot is pointed to the current dir inode */
	d = erofs_d_alloc(dir, ".");
	if (IS_ERR(d))
		return PTR_ERR(d);
	d->inode = erofs_igrab(dir);
	d->type = EROFS_FT_DIR;

	/* dotdot is pointed to the parent dir */
	d = erofs_d_alloc(dir, "..");
	if (IS_ERR(d))
		return PTR_ERR(d);
	d->inode = erofs_igrab(erofs_parent_inode(dir));
	d->type = EROFS_FT_DIR;

	dir->i_nlink = 2;
	return 0;
}

static int erofs_prepare_dir_file(struct erofs_inode *dir,
				  unsigned int nr_subdirs)
{
	struct erofs_sb_info *sbi = dir->sbi;
	struct erofs_dentry *d, *n, **sorted_d;
	unsigned int i;
	unsigned int d_size = 0;

	sorted_d = malloc(nr_subdirs * sizeof(d));
	if (!sorted_d)
		return -ENOMEM;
	i = 0;
	list_for_each_entry_safe(d, n, &dir->i_subdirs, d_child) {
		list_del(&d->d_child);
		sorted_d[i++] = d;
	}
	DBG_BUGON(i != nr_subdirs);
	qsort(sorted_d, nr_subdirs, sizeof(d), comp_subdir);
	for (i = 0; i < nr_subdirs; i++)
		list_add_tail(&sorted_d[i]->d_child, &dir->i_subdirs);
	free(sorted_d);

	/* let's calculate dir size */
	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		int len = d->namelen + sizeof(struct erofs_dirent);

		if (erofs_blkoff(sbi, d_size) + len > erofs_blksiz(sbi))
			d_size = round_up(d_size, erofs_blksiz(sbi));
		d_size += len;
	}
	dir->i_size = d_size;

	/* no compression for all dirs */
	dir->datalayout = EROFS_INODE_FLAT_INLINE;

	/* it will be used in erofs_prepare_inode_buffer */
	dir->idata_size = d_size % erofs_blksiz(sbi);
	return 0;
}

static void fill_dirblock(char *buf, unsigned int size, unsigned int q,
			  struct erofs_dentry *head, struct erofs_dentry *end)
{
	unsigned int p = 0;

	/* write out all erofs_dirents + filenames */
	while (head != end) {
		const unsigned int namelen = head->namelen;
		struct erofs_dirent d = {
			.nid = cpu_to_le64(head->nid),
			.nameoff = cpu_to_le16(q),
			.file_type = head->type,
		};

		memcpy(buf + p, &d, sizeof(d));
		memcpy(buf + q, head->name, namelen);
		p += sizeof(d);
		q += namelen;

		head = list_next_entry(head, d_child);
	}
	memset(buf + q, 0, size - q);
}

static int write_dirblock(struct erofs_sb_info *sbi,
			  unsigned int q, struct erofs_dentry *head,
			  struct erofs_dentry *end, erofs_blk_t blkaddr)
{
	char buf[EROFS_MAX_BLOCK_SIZE];

	fill_dirblock(buf, erofs_blksiz(sbi), q, head, end);
	return erofs_blk_write(sbi, buf, blkaddr, 1);
}

erofs_nid_t erofs_lookupnid(struct erofs_inode *inode)
{
	struct erofs_buffer_head *const bh = inode->bh;
	struct erofs_sb_info *sbi = inode->sbi;
	erofs_off_t off, meta_offset;

	if (bh && (long long)inode->nid <= 0) {
		erofs_mapbh(NULL, bh->block);
		off = erofs_btell(bh, false);

		meta_offset = erofs_pos(sbi, sbi->meta_blkaddr);
		DBG_BUGON(off < meta_offset);
		inode->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
		erofs_dbg("Assign nid %llu to file %s (mode %05o)",
			  inode->nid, inode->i_srcpath, inode->i_mode);
	}
	if (__erofs_unlikely(IS_ROOT(inode)) && inode->nid > 0xffff)
		return sbi->root_nid;
	return inode->nid;
}

static void erofs_d_invalidate(struct erofs_dentry *d)
{
	struct erofs_inode *const inode = d->inode;

	if (d->validnid)
		return;
	d->nid = erofs_lookupnid(inode);
	d->validnid = true;
	erofs_iput(inode);
}

static int erofs_rebuild_inode_fix_pnid(struct erofs_inode *parent,
					erofs_nid_t nid)
{
	struct erofs_inode dir = {
		.sbi = parent->sbi,
		.nid = nid
	};
	unsigned int bsz = erofs_blksiz(dir.sbi);
	unsigned int err, isz;
	erofs_off_t boff, off;
	erofs_nid_t pnid;
	bool fixed = false;

	err = erofs_read_inode_from_disk(&dir);
	if (err)
		return err;

	if (!S_ISDIR(dir.i_mode))
		return -ENOTDIR;

	if (dir.datalayout != EROFS_INODE_FLAT_INLINE &&
	    dir.datalayout != EROFS_INODE_FLAT_PLAIN)
		return -EOPNOTSUPP;

	pnid = erofs_lookupnid(parent);
	isz = dir.inode_isize + dir.xattr_isize;
	boff = erofs_pos(dir.sbi, dir.u.i_blkaddr);
	for (off = 0; off < dir.i_size; off += bsz) {
		char buf[EROFS_MAX_BLOCK_SIZE];
		struct erofs_dirent *de = (struct erofs_dirent *)buf;
		unsigned int nameoff, count, de_nameoff;

		count = min_t(erofs_off_t, bsz, dir.i_size - off);
		err = erofs_pread(&dir, buf, count, off);
		if (err)
			return err;

		nameoff = le16_to_cpu(de->nameoff);
		if (nameoff < sizeof(struct erofs_dirent) ||
		    nameoff >= count) {
			erofs_err("invalid de[0].nameoff %u @ nid %llu, offset %llu",
				  nameoff, dir.nid | 0ULL, off | 0ULL);
			return -EFSCORRUPTED;
		}

		while ((char *)de < buf + nameoff) {
			de_nameoff = le16_to_cpu(de->nameoff);
			if (((char *)(de + 1) >= buf + nameoff ?
				strnlen(buf + de_nameoff, count - de_nameoff) == 2 :
				le16_to_cpu(de[1].nameoff) == de_nameoff + 2) &&
			   !memcmp(buf + de_nameoff, "..", 2)) {
				if (de->nid == cpu_to_le64(pnid))
					return 0;
				de->nid = cpu_to_le64(pnid);
				fixed = true;
				break;
			}
			++de;
		}

		if (!fixed)
			continue;
		err = erofs_dev_write(dir.sbi, buf,
			(off + bsz > dir.i_size &&
				dir.datalayout == EROFS_INODE_FLAT_INLINE ?
				erofs_iloc(&dir) + isz : boff + off), count);
		erofs_dbg("directory %llu pNID is updated to %llu",
			  nid | 0ULL, pnid | 0ULL);
		break;
	}
	if (err || fixed)
		return err;

	erofs_err("directory data %llu is corrupted (\"..\" not found)",
		  nid | 0ULL);
	return -EFSCORRUPTED;
}

static int erofs_write_dir_file(struct erofs_inode *dir)
{
	struct erofs_dentry *head = list_first_entry(&dir->i_subdirs,
						     struct erofs_dentry,
						     d_child);
	struct erofs_sb_info *sbi = dir->sbi;
	struct erofs_dentry *d;
	int ret;
	unsigned int q, used, blkno;

	q = used = blkno = 0;

	/* allocate dir main data */
	ret = erofs_allocate_inode_bh_data(dir, erofs_blknr(sbi, dir->i_size));
	if (ret)
		return ret;

	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		unsigned int len = d->namelen + sizeof(struct erofs_dirent);

		/* XXX: a bit hacky, but to avoid another traversal */
		if (d->validnid && d->type == EROFS_FT_DIR) {
			ret = erofs_rebuild_inode_fix_pnid(dir, d->nid);
			if (ret)
				return ret;
		}

		erofs_d_invalidate(d);
		if (used + len > erofs_blksiz(sbi)) {
			ret = write_dirblock(sbi, q, head, d,
					     dir->u.i_blkaddr + blkno);
			if (ret)
				return ret;

			head = d;
			q = used = 0;
			++blkno;
		}
		used += len;
		q += sizeof(struct erofs_dirent);
	}

	DBG_BUGON(used > erofs_blksiz(sbi));
	if (used == erofs_blksiz(sbi)) {
		DBG_BUGON(dir->i_size % erofs_blksiz(sbi));
		DBG_BUGON(dir->idata_size);
		return write_dirblock(sbi, q, head, d, dir->u.i_blkaddr + blkno);
	}
	DBG_BUGON(used != dir->i_size % erofs_blksiz(sbi));
	if (used) {
		/* fill tail-end dir block */
		dir->idata = malloc(used);
		if (!dir->idata)
			return -ENOMEM;
		DBG_BUGON(used != dir->idata_size);
		fill_dirblock(dir->idata, dir->idata_size, q, head, d);
	}
	return 0;
}

int erofs_write_file_from_buffer(struct erofs_inode *inode, char *buf)
{
	struct erofs_sb_info *sbi = inode->sbi;
	const unsigned int nblocks = erofs_blknr(sbi, inode->i_size);
	int ret;

	inode->datalayout = EROFS_INODE_FLAT_INLINE;

	ret = erofs_allocate_inode_bh_data(inode, nblocks);
	if (ret)
		return ret;

	if (nblocks)
		erofs_blk_write(sbi, buf, inode->u.i_blkaddr, nblocks);
	inode->idata_size = inode->i_size % erofs_blksiz(sbi);
	if (inode->idata_size) {
		inode->idata = malloc(inode->idata_size);
		if (!inode->idata)
			return -ENOMEM;
		memcpy(inode->idata, buf + erofs_pos(sbi, nblocks),
		       inode->idata_size);
	}
	return 0;
}

/* rules to decide whether a file could be compressed or not */
static bool erofs_file_is_compressible(struct erofs_inode *inode)
{
	if (cfg.c_compress_hints_file)
		return z_erofs_apply_compress_hints(inode);
	return true;
}

static int write_uncompressed_file_from_fd(struct erofs_inode *inode, int fd)
{
	struct erofs_sb_info *sbi = inode->sbi;
	erofs_blk_t nblocks, i;
	unsigned int len;
	int ret;

	inode->datalayout = EROFS_INODE_FLAT_INLINE;
	nblocks = inode->i_size >> sbi->blkszbits;

	ret = erofs_allocate_inode_bh_data(inode, nblocks);
	if (ret)
		return ret;

	for (i = 0; i < nblocks; i += (len >> sbi->blkszbits)) {
		len = min_t(u64, round_down(UINT_MAX, 1U << sbi->blkszbits),
			    erofs_pos(sbi, nblocks - i));
		ret = erofs_io_xcopy(&sbi->bdev,
				     erofs_pos(sbi, inode->u.i_blkaddr + i),
				     &((struct erofs_vfile){ .fd = fd }), len,
			inode->datasource == EROFS_INODE_DATA_SOURCE_DISKBUF);
		if (ret)
			return ret;
	}

	/* read the tail-end data */
	inode->idata_size = inode->i_size % erofs_blksiz(sbi);
	if (inode->idata_size) {
		inode->idata = malloc(inode->idata_size);
		if (!inode->idata)
			return -ENOMEM;

		ret = read(fd, inode->idata, inode->idata_size);
		if (ret < inode->idata_size) {
			free(inode->idata);
			inode->idata = NULL;
			return -EIO;
		}
	}
	return 0;
}

int erofs_write_unencoded_file(struct erofs_inode *inode, int fd, u64 fpos)
{
	if (cfg.c_chunkbits) {
		inode->u.chunkbits = cfg.c_chunkbits;
		/* chunk indexes when explicitly specified */
		inode->u.chunkformat = 0;
		if (cfg.c_force_chunkformat == FORCE_INODE_CHUNK_INDEXES)
			inode->u.chunkformat = EROFS_CHUNK_FORMAT_INDEXES;
		return erofs_blob_write_chunked_file(inode, fd, fpos);
	}

	/* fallback to all data uncompressed */
	return write_uncompressed_file_from_fd(inode, fd);
}

int erofs_iflush(struct erofs_inode *inode)
{
	const u16 icount = EROFS_INODE_XATTR_ICOUNT(inode->xattr_isize);
	struct erofs_sb_info *sbi = inode->sbi;
	erofs_off_t off;
	union {
		struct erofs_inode_compact dic;
		struct erofs_inode_extended die;
	} u = {};
	union erofs_inode_i_u u1;
	int ret;

	if (inode->bh)
		off = erofs_btell(inode->bh, false);
	else
		off = erofs_iloc(inode);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
	    S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode))
		u1.rdev = cpu_to_le32(inode->u.i_rdev);
	else if (is_inode_layout_compression(inode))
		u1.blocks_lo = cpu_to_le32(inode->u.i_blocks);
	else if (inode->datalayout == EROFS_INODE_CHUNK_BASED)
		u1.c.format = cpu_to_le16(inode->u.chunkformat);
	else
		u1.startblk_lo = cpu_to_le32(inode->u.i_blkaddr);

	switch (inode->inode_isize) {
	case sizeof(struct erofs_inode_compact):
		u.dic.i_format = cpu_to_le16(0 | (inode->datalayout << 1));
		u.dic.i_xattr_icount = cpu_to_le16(icount);
		u.dic.i_mode = cpu_to_le16(inode->i_mode);
		u.dic.i_nb.nlink = cpu_to_le16(inode->i_nlink);
		u.dic.i_size = cpu_to_le32((u32)inode->i_size);

		u.dic.i_ino = cpu_to_le32(inode->i_ino[0]);

		u.dic.i_uid = cpu_to_le16((u16)inode->i_uid);
		u.dic.i_gid = cpu_to_le16((u16)inode->i_gid);
		u.dic.i_u = u1;
		break;
	case sizeof(struct erofs_inode_extended):
		u.die.i_format = cpu_to_le16(1 | (inode->datalayout << 1));
		u.die.i_xattr_icount = cpu_to_le16(icount);
		u.die.i_mode = cpu_to_le16(inode->i_mode);
		u.die.i_nlink = cpu_to_le32(inode->i_nlink);
		u.die.i_size = cpu_to_le64(inode->i_size);

		u.die.i_ino = cpu_to_le32(inode->i_ino[0]);

		u.die.i_uid = cpu_to_le32(inode->i_uid);
		u.die.i_gid = cpu_to_le32(inode->i_gid);

		u.die.i_mtime = cpu_to_le64(inode->i_mtime);
		u.die.i_mtime_nsec = cpu_to_le32(inode->i_mtime_nsec);
		u.die.i_u = u1;
		break;
	default:
		erofs_err("unsupported on-disk inode version of nid %llu",
			  (unsigned long long)inode->nid);
		BUG_ON(1);
	}

	ret = erofs_dev_write(sbi, &u, off, inode->inode_isize);
	if (ret)
		return ret;
	off += inode->inode_isize;

	if (inode->xattr_isize) {
		char *xattrs = erofs_export_xattr_ibody(inode);

		if (IS_ERR(xattrs))
			return PTR_ERR(xattrs);

		ret = erofs_dev_write(sbi, xattrs, off, inode->xattr_isize);
		free(xattrs);
		if (ret)
			return ret;

		off += inode->xattr_isize;
	}

	if (inode->extent_isize) {
		if (inode->datalayout == EROFS_INODE_CHUNK_BASED) {
			ret = erofs_blob_write_chunk_indexes(inode, off);
			if (ret)
				return ret;
		} else {
			/* write compression metadata */
			off = roundup(off, 8);
			ret = erofs_dev_write(sbi, inode->compressmeta, off,
					      inode->extent_isize);
			if (ret)
				return ret;
		}
	}
	return 0;
}

static int erofs_bh_flush_write_inode(struct erofs_buffer_head *bh)
{
	struct erofs_inode *inode = bh->fsprivate;
	int ret;

	DBG_BUGON(inode->bh != bh);
	ret = erofs_iflush(inode);
	if (ret)
		return ret;
	inode->bh = NULL;
	erofs_iput(inode);
	return erofs_bh_flush_generic_end(bh);
}

static struct erofs_bhops erofs_write_inode_bhops = {
	.flush = erofs_bh_flush_write_inode,
};

static int erofs_prepare_tail_block(struct erofs_inode *inode)
{
	struct erofs_sb_info *sbi = inode->sbi;
	struct erofs_buffer_head *bh;
	int ret;

	if (!inode->idata_size)
		return 0;

	bh = inode->bh_data;
	if (bh) {
		/* expend a block as the tail block (should be successful) */
		ret = erofs_bh_balloon(bh, erofs_blksiz(sbi));
		if (ret != erofs_blksiz(sbi)) {
			DBG_BUGON(1);
			return -EIO;
		}
	} else {
		inode->lazy_tailblock = true;
	}
	if (is_inode_layout_compression(inode))
		inode->u.i_blocks += 1;
	return 0;
}

static int erofs_prepare_inode_buffer(struct erofs_inode *inode)
{
	struct erofs_bufmgr *bmgr = inode->sbi->bmgr;
	unsigned int inodesize;
	struct erofs_buffer_head *bh, *ibh;

	DBG_BUGON(inode->bh || inode->bh_inline);

	inodesize = inode->inode_isize + inode->xattr_isize;
	if (inode->extent_isize)
		inodesize = roundup(inodesize, 8) + inode->extent_isize;

	if (inode->datalayout == EROFS_INODE_FLAT_PLAIN)
		goto noinline;

	/* TODO: tailpacking inline of chunk-based format isn't finalized */
	if (inode->datalayout == EROFS_INODE_CHUNK_BASED)
		goto noinline;

	if (!is_inode_layout_compression(inode)) {
		if (!cfg.c_inline_data && S_ISREG(inode->i_mode)) {
			inode->datalayout = EROFS_INODE_FLAT_PLAIN;
			goto noinline;
		}
		/*
		 * If the file sizes of uncompressed files are block-aligned,
		 * should use the EROFS_INODE_FLAT_PLAIN data layout.
		 */
		if (!inode->idata_size)
			inode->datalayout = EROFS_INODE_FLAT_PLAIN;
	}

	bh = erofs_balloc(bmgr, INODE, inodesize, inode->idata_size);
	if (bh == ERR_PTR(-ENOSPC)) {
		int ret;

		if (is_inode_layout_compression(inode))
			z_erofs_drop_inline_pcluster(inode);
		else
			inode->datalayout = EROFS_INODE_FLAT_PLAIN;
noinline:
		/* expend an extra block for tail-end data */
		ret = erofs_prepare_tail_block(inode);
		if (ret)
			return ret;
		bh = erofs_balloc(bmgr, INODE, inodesize, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		DBG_BUGON(inode->bh_inline);
	} else if (IS_ERR(bh)) {
		return PTR_ERR(bh);
	} else if (inode->idata_size) {
		if (is_inode_layout_compression(inode)) {
			DBG_BUGON(!cfg.c_ztailpacking);
			erofs_dbg("Inline %scompressed data (%u bytes) to %s",
				  inode->compressed_idata ? "" : "un",
				  inode->idata_size, inode->i_srcpath);
			erofs_sb_set_ztailpacking(inode->sbi);
		} else {
			inode->datalayout = EROFS_INODE_FLAT_INLINE;
			erofs_dbg("Inline tail-end data (%u bytes) to %s",
				  inode->idata_size, inode->i_srcpath);
		}

		/* allocate inline buffer */
		ibh = erofs_battach(bh, META, inode->idata_size);
		if (IS_ERR(ibh))
			return PTR_ERR(ibh);

		ibh->op = &erofs_skip_write_bhops;
		inode->bh_inline = ibh;
	}

	bh->fsprivate = erofs_igrab(inode);
	bh->op = &erofs_write_inode_bhops;
	inode->bh = bh;
	inode->i_ino[0] = ++inode->sbi->inos;  /* inode serial number */
	return 0;
}

static int erofs_bh_flush_write_inline(struct erofs_buffer_head *bh)
{
	struct erofs_inode *const inode = bh->fsprivate;
	const erofs_off_t off = erofs_btell(bh, false);
	int ret;

	ret = erofs_dev_write(inode->sbi, inode->idata, off, inode->idata_size);
	if (ret)
		return ret;

	free(inode->idata);
	inode->idata = NULL;

	erofs_iput(inode);
	return erofs_bh_flush_generic_end(bh);
}

static struct erofs_bhops erofs_write_inline_bhops = {
	.flush = erofs_bh_flush_write_inline,
};

static int erofs_write_tail_end(struct erofs_inode *inode)
{
	static const u8 zeroed[EROFS_MAX_BLOCK_SIZE];
	struct erofs_sb_info *sbi = inode->sbi;
	struct erofs_buffer_head *bh, *ibh;

	bh = inode->bh_data;

	if (!inode->idata_size)
		goto out;

	DBG_BUGON(!inode->idata);
	/* have enough room to inline data */
	if (inode->bh_inline) {
		ibh = inode->bh_inline;

		ibh->fsprivate = erofs_igrab(inode);
		ibh->op = &erofs_write_inline_bhops;
	} else {
		struct iovec iov[2];
		erofs_off_t pos;
		int ret;
		bool h0;

		if (!bh) {
			bh = erofs_balloc(sbi->bmgr,
					  S_ISDIR(inode->i_mode) ? DIRA: DATA,
					  erofs_blksiz(sbi), 0);
			if (IS_ERR(bh))
				return PTR_ERR(bh);
			bh->op = &erofs_skip_write_bhops;

			/* get blkaddr of bh */
			ret = erofs_mapbh(NULL, bh->block);
			inode->u.i_blkaddr = bh->block->blkaddr;
			inode->bh_data = bh;
		} else {
			if (inode->lazy_tailblock) {
				/* expend a tail block (should be successful) */
				ret = erofs_bh_balloon(bh, erofs_blksiz(sbi));
				if (ret != erofs_blksiz(sbi)) {
					DBG_BUGON(1);
					return -EIO;
				}
				inode->lazy_tailblock = false;
			}
			ret = erofs_mapbh(NULL, bh->block);
		}
		DBG_BUGON(ret < 0);
		pos = erofs_btell(bh, true) - erofs_blksiz(sbi);

		/* 0'ed data should be padded at head for 0padding conversion */
		h0 = erofs_sb_has_lz4_0padding(sbi) && inode->compressed_idata;
		DBG_BUGON(inode->idata_size > erofs_blksiz(sbi));

		iov[h0] = (struct iovec) { .iov_base = inode->idata,
					   .iov_len = inode->idata_size };
		iov[!h0] = (struct iovec) { .iov_base = (u8 *)zeroed,
				erofs_blksiz(sbi) - inode->idata_size };
		ret = erofs_io_pwritev(&sbi->bdev, iov, 2, pos);
		if (ret < 0)
			return ret;
		else if (ret < erofs_blksiz(sbi))
			return -EIO;

		inode->idata_size = 0;
		free(inode->idata);
		inode->idata = NULL;
	}
out:
	/* now bh_data can drop directly */
	if (bh) {
		/*
		 * Don't leave DATA buffers which were written in the global
		 * buffer list. It will make balloc() slowly.
		 */
		erofs_bdrop(bh, false);
		inode->bh_data = NULL;
	}
	return 0;
}

static bool erofs_should_use_inode_extended(struct erofs_inode *inode,
					    const char *path)
{
	if (cfg.c_force_inodeversion == FORCE_INODE_EXTENDED)
		return true;
	if (inode->i_size > UINT_MAX)
		return true;
	if (erofs_is_packed_inode(inode))
		return false;
	if (inode->i_uid > USHRT_MAX)
		return true;
	if (inode->i_gid > USHRT_MAX)
		return true;
	if (inode->i_nlink > USHRT_MAX)
		return true;
	if (path != EROFS_PACKED_INODE &&
	    (inode->i_mtime != inode->sbi->epoch ||
	     inode->i_mtime_nsec != inode->sbi->fixed_nsec) &&
	    !cfg.c_ignore_mtime)
		return true;
	return false;
}

u32 erofs_new_encode_dev(dev_t dev)
{
	const unsigned int major = major(dev);
	const unsigned int minor = minor(dev);

	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

#ifdef WITH_ANDROID
int erofs_droid_inode_fsconfig(struct erofs_inode *inode,
			       struct stat *st,
			       const char *path)
{
	/* filesystem_config does not preserve file type bits */
	mode_t stat_file_type_mask = st->st_mode & S_IFMT;
	unsigned int uid = 0, gid = 0, mode = 0;
	const char *fspath;
	char *decorated = NULL;

	inode->capabilities = 0;
	if (!cfg.fs_config_file && !cfg.mount_point)
		return 0;
	/* avoid loading special inodes */
	if (path == EROFS_PACKED_INODE)
		return 0;

	if (!cfg.mount_point ||
	/* have to drop the mountpoint for rootdir of canned fsconfig */
	    (cfg.fs_config_file && erofs_fspath(path)[0] == '\0')) {
		fspath = erofs_fspath(path);
	} else {
		if (asprintf(&decorated, "%s/%s", cfg.mount_point,
			     erofs_fspath(path)) <= 0)
			return -ENOMEM;
		fspath = decorated;
	}

	if (cfg.fs_config_file)
		canned_fs_config(fspath, S_ISDIR(st->st_mode),
				 cfg.target_out_path,
				 &uid, &gid, &mode, &inode->capabilities);
	else
		fs_config(fspath, S_ISDIR(st->st_mode),
			  cfg.target_out_path,
			  &uid, &gid, &mode, &inode->capabilities);

	erofs_dbg("/%s -> mode = 0x%x, uid = 0x%x, gid = 0x%x, capabilities = 0x%" PRIx64,
		  fspath, mode, uid, gid, inode->capabilities);

	if (decorated)
		free(decorated);
	st->st_uid = uid;
	st->st_gid = gid;
	st->st_mode = mode | stat_file_type_mask;
	return 0;
}
#else
static int erofs_droid_inode_fsconfig(struct erofs_inode *inode,
				      struct stat *st,
				      const char *path)
{
	return 0;
}
#endif

int __erofs_fill_inode(struct erofs_inode *inode, struct stat *st,
		       const char *path)
{
	int err = erofs_droid_inode_fsconfig(inode, st, path);
	struct erofs_sb_info *sbi = inode->sbi;

	if (err)
		return err;

	inode->i_uid = cfg.c_uid == -1 ? st->st_uid : cfg.c_uid;
	inode->i_gid = cfg.c_gid == -1 ? st->st_gid : cfg.c_gid;

	if (inode->i_uid + cfg.c_uid_offset < 0)
		erofs_err("uid overflow @ %s", path);
	inode->i_uid += cfg.c_uid_offset;

	if (inode->i_gid + cfg.c_gid_offset < 0)
		erofs_err("gid overflow @ %s", path);
	inode->i_gid += cfg.c_gid_offset;

	if (path == EROFS_PACKED_INODE) {
		inode->i_mtime = sbi->epoch + sbi->build_time;
		inode->i_mtime_nsec = sbi->fixed_nsec;
		return 0;
	}
	inode->i_mtime = st->st_mtime;
	inode->i_mtime_nsec = ST_MTIM_NSEC(st);

	switch (cfg.c_timeinherit) {
	case TIMESTAMP_CLAMPING:
		if (inode->i_mtime < sbi->epoch + sbi->build_time)
			break;
	case TIMESTAMP_FIXED:
		inode->i_mtime = sbi->epoch + sbi->build_time;
		inode->i_mtime_nsec = sbi->fixed_nsec;
	default:
		break;
	}
	return 0;
}

static int erofs_fill_inode(struct erofs_inode *inode, struct stat *st,
			    const char *path)
{
	int err = __erofs_fill_inode(inode, st, path);

	if (err)
		return err;

	inode->i_mode = st->st_mode;
	inode->i_nlink = 1;	/* fix up later if needed */

	switch (inode->i_mode & S_IFMT) {
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		inode->u.i_rdev = erofs_new_encode_dev(st->st_rdev);
	case S_IFDIR:
		inode->i_size = 0;
		break;
	case S_IFREG:
	case S_IFLNK:
		inode->i_size = st->st_size;
		break;
	default:
		return -EINVAL;
	}

	inode->i_srcpath = strdup(path);
	if (!inode->i_srcpath)
		return -ENOMEM;

	if (erofs_should_use_inode_extended(inode, path)) {
		if (cfg.c_force_inodeversion == FORCE_INODE_COMPACT) {
			erofs_err("file %s cannot be in compact form",
				  inode->i_srcpath);
			return -EINVAL;
		}
		inode->inode_isize = sizeof(struct erofs_inode_extended);
	} else {
		inode->inode_isize = sizeof(struct erofs_inode_compact);
	}

	inode->dev = st->st_dev;
	inode->i_ino[1] = st->st_ino;
	erofs_insert_ihash(inode);
	return 0;
}

struct erofs_inode *erofs_new_inode(struct erofs_sb_info *sbi)
{
	struct erofs_inode *inode;

	inode = calloc(1, sizeof(struct erofs_inode));
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->sbi = sbi;
	/*
	 * By default, newly allocated in-memory inodes are associated with
	 * the target filesystem rather than any other foreign sources.
	 */
	inode->dev = sbi->dev;
	inode->i_count = 1;
	inode->datalayout = EROFS_INODE_FLAT_PLAIN;

	init_list_head(&inode->i_hash);
	init_list_head(&inode->i_subdirs);
	init_list_head(&inode->i_xattrs);
	return inode;
}

/* get the inode from the source path */
static struct erofs_inode *erofs_iget_from_srcpath(struct erofs_sb_info *sbi,
						   const char *path)
{
	struct stat st;
	struct erofs_inode *inode;
	int ret;

	ret = lstat(path, &st);
	if (ret)
		return ERR_PTR(-errno);

	/*
	 * lookup in hash table first, if it already exists we have a
	 * hard-link, just return it. Also don't lookup for directories
	 * since hard-link directory isn't allowed.
	 */
	if (!S_ISDIR(st.st_mode) && (!cfg.c_hard_dereference)) {
		inode = erofs_iget(st.st_dev, st.st_ino);
		if (inode)
			return inode;
	}

	/* cannot find in the inode cache */
	inode = erofs_new_inode(sbi);
	if (IS_ERR(inode))
		return inode;

	ret = erofs_fill_inode(inode, &st, path);
	if (ret) {
		erofs_iput(inode);
		return ERR_PTR(ret);
	}
	return inode;
}

static void erofs_fixup_meta_blkaddr(struct erofs_inode *rootdir)
{
	const erofs_off_t rootnid_maxoffset = 0xffff << EROFS_ISLOTBITS;
	struct erofs_buffer_head *const bh = rootdir->bh;
	struct erofs_sb_info *sbi = rootdir->sbi;
	erofs_off_t off, meta_offset;

	erofs_mapbh(NULL, bh->block);
	off = erofs_btell(bh, false);

	if (off > rootnid_maxoffset)
		meta_offset = round_up(off - rootnid_maxoffset, erofs_blksiz(sbi));
	else
		meta_offset = 0;
	sbi->meta_blkaddr = erofs_blknr(sbi, meta_offset);
	rootdir->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
}

static int erofs_inode_reserve_data_blocks(struct erofs_inode *inode)
{
	struct erofs_sb_info *sbi = inode->sbi;
	erofs_off_t alignedsz = round_up(inode->i_size, erofs_blksiz(sbi));
	erofs_blk_t nblocks = alignedsz >> sbi->blkszbits;
	struct erofs_buffer_head *bh;

	/* allocate data blocks */
	bh = erofs_balloc(sbi->bmgr, DATA, alignedsz, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);

	/* get blkaddr of the bh */
	(void)erofs_mapbh(NULL, bh->block);

	/* write blocks except for the tail-end block */
	inode->u.i_blkaddr = bh->block->blkaddr;
	erofs_bdrop(bh, false);

	inode->datalayout = EROFS_INODE_FLAT_PLAIN;
	tarerofs_blocklist_write(inode->u.i_blkaddr, nblocks, inode->i_ino[1],
				 alignedsz - inode->i_size);
	return 0;
}

struct erofs_mkfs_job_ndir_ctx {
	struct erofs_inode *inode;
	void *ictx;
	int fd;
	u64 fpos;
};

static int erofs_mkfs_job_write_file(struct erofs_mkfs_job_ndir_ctx *ctx)
{
	struct erofs_inode *inode = ctx->inode;
	int ret;

	if (inode->datasource == EROFS_INODE_DATA_SOURCE_DISKBUF &&
	    lseek(ctx->fd, ctx->fpos, SEEK_SET) < 0) {
		ret = -errno;
		goto out;
	}

	if (ctx->ictx) {
		ret = erofs_write_compressed_file(ctx->ictx);
		if (ret != -ENOSPC)
			goto out;
		if (lseek(ctx->fd, ctx->fpos, SEEK_SET) < 0) {
			ret = -errno;
			goto out;
		}
	}
	/* fallback to all data uncompressed */
	ret = erofs_write_unencoded_file(inode, ctx->fd, ctx->fpos);
out:
	if (inode->datasource == EROFS_INODE_DATA_SOURCE_DISKBUF) {
		erofs_diskbuf_close(inode->i_diskbuf);
		free(inode->i_diskbuf);
		inode->i_diskbuf = NULL;
		inode->datasource = EROFS_INODE_DATA_SOURCE_NONE;
	} else {
		DBG_BUGON(ctx->fd < 0);
		close(ctx->fd);
	}
	return ret;
}

static int erofs_mkfs_handle_nondirectory(struct erofs_mkfs_job_ndir_ctx *ctx)
{
	struct erofs_inode *inode = ctx->inode;
	int ret = 0;

	if (S_ISLNK(inode->i_mode)) {
		char *symlink = inode->i_link;

		if (!symlink) {
			symlink = malloc(inode->i_size);
			if (!symlink)
				return -ENOMEM;
			ret = readlink(inode->i_srcpath, symlink, inode->i_size);
			if (ret < 0) {
				free(symlink);
				return -errno;
			}
		}
		ret = erofs_write_file_from_buffer(inode, symlink);
		free(symlink);
		inode->i_link = NULL;
	} else if (inode->i_size) {
		if (inode->datasource == EROFS_INODE_DATA_SOURCE_RESVSP)
			ret = erofs_inode_reserve_data_blocks(inode);
		else if (ctx->fd >= 0)
			ret = erofs_mkfs_job_write_file(ctx);
	}
	if (ret)
		return ret;
	erofs_prepare_inode_buffer(inode);
	erofs_write_tail_end(inode);
	return 0;
}

enum erofs_mkfs_jobtype {	/* ordered job types */
	EROFS_MKFS_JOB_NDIR,
	EROFS_MKFS_JOB_DIR,
	EROFS_MKFS_JOB_DIR_BH,
	EROFS_MKFS_JOB_MAX
};

struct erofs_mkfs_jobitem {
	enum erofs_mkfs_jobtype type;
	union {
		struct erofs_inode *inode;
		struct erofs_mkfs_job_ndir_ctx ndir;
	} u;
};

static int erofs_mkfs_jobfn(struct erofs_mkfs_jobitem *item)
{
	struct erofs_inode *inode = item->u.inode;
	int ret;

	if (item->type >= EROFS_MKFS_JOB_MAX)
		return 1;

	if (item->type == EROFS_MKFS_JOB_NDIR)
		return erofs_mkfs_handle_nondirectory(&item->u.ndir);

	if (item->type == EROFS_MKFS_JOB_DIR) {
		ret = erofs_prepare_inode_buffer(inode);
		if (ret)
			return ret;
		inode->bh->op = &erofs_skip_write_bhops;
		return 0;
	}

	if (item->type == EROFS_MKFS_JOB_DIR_BH) {
		ret = erofs_write_dir_file(inode);
		if (ret)
			return ret;
		erofs_write_tail_end(inode);
		inode->bh->op = &erofs_write_inode_bhops;
		erofs_iput(inode);
		return 0;
	}
	return -EINVAL;
}

#ifdef EROFS_MT_ENABLED

struct erofs_mkfs_dfops {
	pthread_t worker;
	pthread_mutex_t lock;
	pthread_cond_t full, empty, drain;
	struct erofs_mkfs_jobitem *queue;
	unsigned int entries, head, tail;
	bool idle;	/* initialize as false before the dfops worker runs */
	bool exited;
};

static void erofs_mkfs_flushjobs(struct erofs_sb_info *sbi)
{
	struct erofs_mkfs_dfops *q = sbi->mkfs_dfops;

	pthread_mutex_lock(&q->lock);
	if (!q->idle)
		pthread_cond_wait(&q->drain, &q->lock);
	pthread_mutex_unlock(&q->lock);
}

static void *erofs_mkfs_top_jobitem(struct erofs_mkfs_dfops *q)
{
	struct erofs_mkfs_jobitem *item;

	pthread_mutex_lock(&q->lock);
	while (q->head == q->tail) {
		/* the worker has handled everything only if sleeping here */
		q->idle = true;
		pthread_cond_signal(&q->drain);
		pthread_cond_wait(&q->empty, &q->lock);
	}
	item = q->queue + (q->head & (q->entries - 1));
	pthread_mutex_unlock(&q->lock);
	return item;
}

static void erofs_mkfs_pop_jobitem(struct erofs_mkfs_dfops *q)
{
	pthread_mutex_lock(&q->lock);
	DBG_BUGON(q->head == q->tail);
	++q->head;
	pthread_cond_signal(&q->full);
	pthread_mutex_unlock(&q->lock);
}

static void *z_erofs_mt_dfops_worker(void *arg)
{
	struct erofs_sb_info *sbi = arg;
	struct erofs_mkfs_dfops *dfops = sbi->mkfs_dfops;
	int ret;

	do {
		struct erofs_mkfs_jobitem *item;

		item = erofs_mkfs_top_jobitem(dfops);
		ret = erofs_mkfs_jobfn(item);
		erofs_mkfs_pop_jobitem(dfops);
	} while (!ret);

	dfops->exited = true;
	if (ret < 0)
		pthread_cond_signal(&dfops->full);
	pthread_exit((void *)(uintptr_t)(ret < 0 ? ret : 0));
}

static int erofs_mkfs_go(struct erofs_sb_info *sbi,
			 enum erofs_mkfs_jobtype type, void *elem, int size)
{
	struct erofs_mkfs_jobitem *item;
	struct erofs_mkfs_dfops *q = sbi->mkfs_dfops;

	pthread_mutex_lock(&q->lock);

	while (q->tail - q->head >= q->entries) {
		if (q->exited) {
			pthread_mutex_unlock(&q->lock);
			return -ECHILD;
		}
		pthread_cond_wait(&q->full, &q->lock);
	}

	item = q->queue + (q->tail++ & (q->entries - 1));
	item->type = type;
	if (size)
		memcpy(&item->u, elem, size);
	q->idle = false;

	pthread_cond_signal(&q->empty);
	pthread_mutex_unlock(&q->lock);
	return 0;
}
#else
static int erofs_mkfs_go(struct erofs_sb_info *sbi,
			 enum erofs_mkfs_jobtype type, void *elem, int size)
{
	struct erofs_mkfs_jobitem item;

	item.type = type;
	memcpy(&item.u, elem, size);
	return erofs_mkfs_jobfn(&item);
}
static void erofs_mkfs_flushjobs(struct erofs_sb_info *sbi)
{
}
#endif

static int erofs_mkfs_handle_directory(struct erofs_inode *dir)
{
	struct erofs_sb_info *sbi = dir->sbi;
	DIR *_dir;
	struct dirent *dp;
	struct erofs_dentry *d;
	unsigned int nr_subdirs, i_nlink;
	int ret;

	_dir = opendir(dir->i_srcpath);
	if (!_dir) {
		erofs_err("failed to opendir at %s: %s",
			  dir->i_srcpath, erofs_strerror(-errno));
		return -errno;
	}

	nr_subdirs = 0;
	i_nlink = 0;
	while (1) {
		char buf[PATH_MAX];
		struct erofs_inode *inode;

		/*
		 * set errno to 0 before calling readdir() in order to
		 * distinguish end of stream and from an error.
		 */
		errno = 0;
		dp = readdir(_dir);
		if (!dp) {
			if (!errno)
				break;
			ret = -errno;
			goto err_closedir;
		}

		if (is_dot_dotdot(dp->d_name)) {
			++i_nlink;
			continue;
		}

		/* skip if it's a exclude file */
		if (erofs_is_exclude_path(dir->i_srcpath, dp->d_name))
			continue;

		d = erofs_d_alloc(dir, dp->d_name);
		if (IS_ERR(d)) {
			ret = PTR_ERR(d);
			goto err_closedir;
		}

		ret = snprintf(buf, PATH_MAX, "%s/%s", dir->i_srcpath, d->name);
		if (ret < 0 || ret >= PATH_MAX)
			goto err_closedir;

		inode = erofs_iget_from_srcpath(sbi, buf);
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			goto err_closedir;
		}
		d->inode = inode;
		d->type = erofs_mode_to_ftype(inode->i_mode);
		i_nlink += S_ISDIR(inode->i_mode);
		erofs_dbg("file %s added (type %u)", buf, d->type);
		nr_subdirs++;
	}
	closedir(_dir);

	ret = erofs_init_empty_dir(dir);
	if (ret)
		return ret;

	ret = erofs_prepare_dir_file(dir, nr_subdirs + 2); /* sort subdirs */
	if (ret)
		return ret;

	/*
	 * if there're too many subdirs as compact form, set nlink=1
	 * rather than upgrade to use extented form instead.
	 */
	if (i_nlink > USHRT_MAX &&
	    dir->inode_isize == sizeof(struct erofs_inode_compact))
		dir->i_nlink = 1;
	else
		dir->i_nlink = i_nlink;

	return erofs_mkfs_go(sbi, EROFS_MKFS_JOB_DIR, &dir, sizeof(dir));

err_closedir:
	closedir(_dir);
	return ret;
}

int erofs_rebuild_load_basedir(struct erofs_inode *dir);

bool erofs_dentry_is_wht(struct erofs_sb_info *sbi, struct erofs_dentry *d)
{
	if (!d->validnid)
		return erofs_inode_is_whiteout(d->inode);
	if (d->type == EROFS_FT_CHRDEV) {
		struct erofs_inode ei = { .sbi = sbi, .nid = d->nid };
		int ret;

		ret = erofs_read_inode_from_disk(&ei);
		if (ret) {
			erofs_err("failed to check DT_WHT: %s",
				  erofs_strerror(ret));
			DBG_BUGON(1);
			return false;
		}
		return erofs_inode_is_whiteout(&ei);
	}
	return false;
}

static int erofs_rebuild_handle_directory(struct erofs_inode *dir,
					  bool incremental)
{
	struct erofs_sb_info *sbi = dir->sbi;
	struct erofs_dentry *d, *n;
	unsigned int nr_subdirs, i_nlink;
	bool delwht = cfg.c_ovlfs_strip && dir->whiteouts;
	int ret;

	nr_subdirs = 0;
	i_nlink = 0;

	list_for_each_entry_safe(d, n, &dir->i_subdirs, d_child) {
		if (delwht && erofs_dentry_is_wht(sbi, d)) {
			erofs_dbg("remove whiteout %s", d->inode->i_srcpath);
			list_del(&d->d_child);
			erofs_d_invalidate(d);
			free(d);
			continue;
		}
		i_nlink += (d->type == EROFS_FT_DIR);
		++nr_subdirs;
	}

	DBG_BUGON(i_nlink < 2);		/* should have `.` and `..` */
	DBG_BUGON(nr_subdirs < i_nlink);
	ret = erofs_prepare_dir_file(dir, nr_subdirs);
	if (ret)
		return ret;

	if (IS_ROOT(dir) && incremental)
		dir->datalayout = EROFS_INODE_FLAT_PLAIN;

	/*
	 * if there're too many subdirs as compact form, set nlink=1
	 * rather than upgrade to use extented form instead.
	 */
	if (i_nlink > USHRT_MAX &&
	    dir->inode_isize == sizeof(struct erofs_inode_compact))
		dir->i_nlink = 1;
	else
		dir->i_nlink = i_nlink;

	return erofs_mkfs_go(sbi, EROFS_MKFS_JOB_DIR, &dir, sizeof(dir));
}

static int erofs_mkfs_handle_inode(struct erofs_inode *inode)
{
	const char *relpath = erofs_fspath(inode->i_srcpath);
	char *trimmed;
	int ret;

	trimmed = erofs_trim_for_progressinfo(relpath[0] ? relpath : "/",
					      sizeof("Processing  ...") - 1);
	erofs_update_progressinfo("Processing %s ...", trimmed);
	free(trimmed);

	ret = erofs_scan_file_xattrs(inode);
	if (ret < 0)
		return ret;

	ret = erofs_prepare_xattr_ibody(inode, false);
	if (ret < 0)
		return ret;

	if (!S_ISDIR(inode->i_mode)) {
		struct erofs_mkfs_job_ndir_ctx ctx = { .inode = inode, .fd = -1 };

		if (!S_ISLNK(inode->i_mode) && inode->i_size) {
			ctx.fd = open(inode->i_srcpath, O_RDONLY | O_BINARY);
			if (ctx.fd < 0)
				return -errno;

			if (cfg.c_compr_opts[0].alg &&
			    erofs_file_is_compressible(inode)) {
				ctx.ictx = erofs_begin_compressed_file(inode,
								ctx.fd, 0);
				if (IS_ERR(ctx.ictx))
					return PTR_ERR(ctx.ictx);
			}
		}
		ret = erofs_mkfs_go(inode->sbi, EROFS_MKFS_JOB_NDIR,
				    &ctx, sizeof(ctx));
	} else {
		ret = erofs_mkfs_handle_directory(inode);
	}
	erofs_info("file /%s dumped (mode %05o)", relpath, inode->i_mode);
	return ret;
}

static int erofs_rebuild_handle_inode(struct erofs_inode *inode,
				      bool incremental)
{
	char *trimmed;
	int ret;

	trimmed = erofs_trim_for_progressinfo(erofs_fspath(inode->i_srcpath),
					      sizeof("Processing  ...") - 1);
	erofs_update_progressinfo("Processing %s ...", trimmed);
	free(trimmed);

	if (erofs_should_use_inode_extended(inode, inode->i_srcpath)) {
		if (cfg.c_force_inodeversion == FORCE_INODE_COMPACT) {
			erofs_err("file %s cannot be in compact form",
				  inode->i_srcpath);
			return -EINVAL;
		}
		inode->inode_isize = sizeof(struct erofs_inode_extended);
	} else {
		inode->inode_isize = sizeof(struct erofs_inode_compact);
	}

	if (incremental && S_ISDIR(inode->i_mode) &&
	    inode->dev == inode->sbi->dev && !inode->opaque) {
		ret = erofs_rebuild_load_basedir(inode);
		if (ret)
			return ret;
	}

	/* strip all unnecessary overlayfs xattrs when ovlfs_strip is enabled */
	if (cfg.c_ovlfs_strip)
		erofs_clear_opaque_xattr(inode);
	else if (inode->whiteouts)
		erofs_set_origin_xattr(inode);

	ret = erofs_prepare_xattr_ibody(inode, incremental && IS_ROOT(inode));
	if (ret < 0)
		return ret;

	if (!S_ISDIR(inode->i_mode)) {
		struct erofs_mkfs_job_ndir_ctx ctx =
			{ .inode = inode, .fd = -1 };

		if (S_ISREG(inode->i_mode) && inode->i_size &&
		    inode->datasource == EROFS_INODE_DATA_SOURCE_DISKBUF) {
			ctx.fd = erofs_diskbuf_getfd(inode->i_diskbuf, &ctx.fpos);
			if (ctx.fd < 0)
				return ret;

			if (cfg.c_compr_opts[0].alg &&
			    erofs_file_is_compressible(inode)) {
				ctx.ictx = erofs_begin_compressed_file(inode,
							ctx.fd, ctx.fpos);
				if (IS_ERR(ctx.ictx))
					return PTR_ERR(ctx.ictx);
			}
		}
		ret = erofs_mkfs_go(inode->sbi, EROFS_MKFS_JOB_NDIR,
				    &ctx, sizeof(ctx));
	} else {
		ret = erofs_rebuild_handle_directory(inode, incremental);
	}
	erofs_info("file %s dumped (mode %05o)", erofs_fspath(inode->i_srcpath),
		   inode->i_mode);
	return ret;
}

static bool erofs_inode_visited(struct erofs_inode *inode)
{
	return (unsigned long)inode->i_parent & 1UL;
}

static void erofs_mark_parent_inode(struct erofs_inode *inode,
				    struct erofs_inode *dir)
{
	inode->i_parent = (void *)((unsigned long)dir | 1);
}

static int erofs_mkfs_dump_tree(struct erofs_inode *root, bool rebuild,
				bool incremental)
{
	struct erofs_sb_info *sbi = root->sbi;
	struct erofs_inode *dumpdir = erofs_igrab(root);
	int err, err2;

	erofs_mark_parent_inode(root, root);	/* rootdir mark */
	root->next_dirwrite = NULL;
	/* update dev/i_ino[1] to keep track of the base image */
	if (incremental) {
		root->dev = root->sbi->dev;
		root->i_ino[1] = sbi->root_nid;
		erofs_remove_ihash(root);
		erofs_insert_ihash(root);
	} else if (cfg.c_root_xattr_isize) {
		if (cfg.c_root_xattr_isize > EROFS_XATTR_ALIGN(
				UINT16_MAX - sizeof(struct erofs_xattr_entry))) {
			erofs_err("Invalid configuration for c_root_xattr_isize: %u (too large)",
				  cfg.c_root_xattr_isize);
			return -EINVAL;
		}
		root->xattr_isize = cfg.c_root_xattr_isize;
	}

	err = !rebuild ? erofs_mkfs_handle_inode(root) :
			erofs_rebuild_handle_inode(root, incremental);
	if (err)
		return err;

	/* assign root NID immediately for non-incremental builds */
	if (!incremental) {
		erofs_mkfs_flushjobs(sbi);
		erofs_fixup_meta_blkaddr(root);
		sbi->root_nid = root->nid;
	}

	do {
		struct erofs_inode *dir = dumpdir;
		/* used for adding sub-directories in reverse order due to FIFO */
		struct erofs_inode *head, **last = &head;
		struct erofs_dentry *d;

		dumpdir = dir->next_dirwrite;
		list_for_each_entry(d, &dir->i_subdirs, d_child) {
			struct erofs_inode *inode = d->inode;

			if (is_dot_dotdot(d->name) || d->validnid)
				continue;

			if (!erofs_inode_visited(inode)) {
				DBG_BUGON(rebuild && (inode->i_nlink == 1 ||
					  S_ISDIR(inode->i_mode)) &&
					  erofs_parent_inode(inode) != dir);
				erofs_mark_parent_inode(inode, dir);

				if (!rebuild)
					err = erofs_mkfs_handle_inode(inode);
				else
					err = erofs_rebuild_handle_inode(inode,
								incremental);
				if (err)
					break;
				if (S_ISDIR(inode->i_mode)) {
					*last = inode;
					last = &inode->next_dirwrite;
					(void)erofs_igrab(inode);
				}
			} else if (!rebuild) {
				++inode->i_nlink;
			}
		}
		*last = dumpdir;	/* fixup the last (or the only) one */
		dumpdir = head;
		err2 = erofs_mkfs_go(sbi, EROFS_MKFS_JOB_DIR_BH,
				    &dir, sizeof(dir));
		if (err || err2)
			return err ? err : err2;
	} while (dumpdir);

	return err;
}

struct erofs_mkfs_buildtree_ctx {
	struct erofs_sb_info *sbi;
	union {
		const char *path;
		struct erofs_inode *root;
	} u;
	bool incremental;
};
#ifndef EROFS_MT_ENABLED
#define __erofs_mkfs_build_tree erofs_mkfs_build_tree
#endif

static int __erofs_mkfs_build_tree(struct erofs_mkfs_buildtree_ctx *ctx)
{
	bool from_path = !!ctx->sbi;
	struct erofs_inode *root;
	int err;

	if (from_path) {
		root = erofs_iget_from_srcpath(ctx->sbi, ctx->u.path);
		if (IS_ERR(root))
			return PTR_ERR(root);
	} else {
		root = ctx->u.root;
	}

	err = erofs_mkfs_dump_tree(root, !from_path, ctx->incremental);
	if (err) {
		if (from_path)
			erofs_iput(root);
		return err;
	}
	ctx->u.root = root;
	return 0;
}

#ifdef EROFS_MT_ENABLED

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

static int erofs_get_fdlimit(void)
{
#if defined(HAVE_SYS_RESOURCE_H) && defined(HAVE_GETRLIMIT)
	struct rlimit rlim;
	int err;

	err = getrlimit(RLIMIT_NOFILE, &rlim);
	if (err < 0)
		return _POSIX_OPEN_MAX;
	if (rlim.rlim_cur == RLIM_INFINITY)
		return 0;
	return rlim.rlim_cur;
#else
	return _POSIX_OPEN_MAX;
#endif
}

static int erofs_mkfs_build_tree(struct erofs_mkfs_buildtree_ctx *ctx)
{
	struct erofs_sb_info *sbi = ctx->sbi ? ctx->sbi : ctx->u.root->sbi;
	struct erofs_mkfs_dfops *q;
	int err, err2;
	void *retval;

	q = calloc(1, sizeof(*q));
	if (!q)
		return -ENOMEM;

	if (cfg.c_mt_async_queue_limit) {
		q->entries = cfg.c_mt_async_queue_limit;
	} else {
		err = roundup_pow_of_two(erofs_get_fdlimit()) >> 1;
		q->entries = err && err < 32768 ? err : 32768;
	}
	erofs_dbg("Set the asynchronous queue size to %u", q->entries);

	q->queue = malloc(q->entries * sizeof(*q->queue));
	if (!q->queue) {
		free(q);
		return -ENOMEM;
	}
	pthread_mutex_init(&q->lock, NULL);
	pthread_cond_init(&q->empty, NULL);
	pthread_cond_init(&q->full, NULL);
	pthread_cond_init(&q->drain, NULL);

	sbi->mkfs_dfops = q;
	err = pthread_create(&sbi->dfops_worker, NULL,
			     z_erofs_mt_dfops_worker, sbi);
	if (err)
		goto fail;

	err = __erofs_mkfs_build_tree(ctx);
	erofs_mkfs_go(sbi, ~0, NULL, 0);
	err2 = pthread_join(sbi->dfops_worker, &retval);
	DBG_BUGON(!q->exited);
	if (!err || err == -ECHILD) {
		err = err2;
		if (!err)
			err = (intptr_t)retval;
	}

fail:
	pthread_cond_destroy(&q->empty);
	pthread_cond_destroy(&q->full);
	pthread_cond_destroy(&q->drain);
	pthread_mutex_destroy(&q->lock);
	free(q->queue);
	free(q);
	return err;
}
#endif

struct erofs_inode *erofs_mkfs_build_tree_from_path(struct erofs_sb_info *sbi,
						    const char *path)
{
	struct erofs_mkfs_buildtree_ctx ctx = {
		.sbi = sbi,
		.u.path = path,
	};
	int err;

	if (!sbi)
		return ERR_PTR(-EINVAL);
	err = erofs_mkfs_build_tree(&ctx);
	if (err)
		return ERR_PTR(err);
	return ctx.u.root;
}

int erofs_rebuild_dump_tree(struct erofs_inode *root, bool incremental)
{
	return erofs_mkfs_build_tree(&((struct erofs_mkfs_buildtree_ctx) {
		.sbi = NULL,
		.u.root = root,
		.incremental = incremental,
	}));
}

struct erofs_inode *erofs_mkfs_build_special_from_fd(struct erofs_sb_info *sbi,
						     int fd, const char *name)
{
	struct stat st;
	struct erofs_inode *inode;
	void *ictx;
	int ret;

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0)
		return ERR_PTR(-errno);

	ret = fstat(fd, &st);
	if (ret)
		return ERR_PTR(-errno);

	inode = erofs_new_inode(sbi);
	if (IS_ERR(inode))
		return inode;

	if (name == EROFS_PACKED_INODE) {
		st.st_uid = st.st_gid = 0;
		st.st_nlink = 0;
	}

	ret = erofs_fill_inode(inode, &st, name);
	if (ret) {
		free(inode);
		return ERR_PTR(ret);
	}

	if (name == EROFS_PACKED_INODE) {
		inode->sbi->packed_nid = EROFS_PACKED_NID_UNALLOCATED;
		inode->nid = inode->sbi->packed_nid;
	}

	if (cfg.c_compr_opts[0].alg &&
	    erofs_file_is_compressible(inode)) {
		ictx = erofs_begin_compressed_file(inode, fd, 0);
		if (IS_ERR(ictx))
			return ERR_CAST(ictx);

		DBG_BUGON(!ictx);
		ret = erofs_write_compressed_file(ictx);
		if (!ret)
			goto out;
		if (ret != -ENOSPC)
			 return ERR_PTR(ret);

		ret = lseek(fd, 0, SEEK_SET);
		if (ret < 0)
			return ERR_PTR(-errno);
	}
	ret = write_uncompressed_file_from_fd(inode, fd);
	if (ret)
		return ERR_PTR(ret);
out:
	erofs_prepare_inode_buffer(inode);
	erofs_write_tail_end(inode);
	return inode;
}

int erofs_fixup_root_inode(struct erofs_inode *root)
{
	struct erofs_sb_info *sbi = root->sbi;
	struct erofs_inode oi;
	unsigned int ondisk_capacity, ondisk_size;
	char *ibuf;
	int err;

	if (sbi->root_nid == root->nid)		/* for most mkfs cases */
		return 0;

	if (root->nid <= 0xffff) {
		sbi->root_nid = root->nid;
		return 0;
	}

	oi = (struct erofs_inode){ .sbi = sbi, .nid = sbi->root_nid };
	err = erofs_read_inode_from_disk(&oi);
	if (err) {
		erofs_err("failed to read root inode: %s",
			  erofs_strerror(err));
		return err;
	}

	if (oi.datalayout != EROFS_INODE_FLAT_INLINE &&
	    oi.datalayout != EROFS_INODE_FLAT_PLAIN)
		return -EOPNOTSUPP;

	ondisk_capacity = oi.inode_isize + oi.xattr_isize;
	if (oi.datalayout == EROFS_INODE_FLAT_INLINE)
		ondisk_capacity += erofs_blkoff(sbi, oi.i_size);

	ondisk_size = root->inode_isize + root->xattr_isize;
	if (root->extent_isize)
		ondisk_size = roundup(ondisk_size, 8) + root->extent_isize;
	ondisk_size += root->idata_size;

	if (ondisk_size > ondisk_capacity) {
		erofs_err("no enough room for the root inode from nid %llu",
			  root->nid);
		return -ENOSPC;
	}

	ibuf = malloc(ondisk_size);
	if (!ibuf)
		return -ENOMEM;
	err = erofs_dev_read(sbi, 0, ibuf, erofs_iloc(root), ondisk_size);
	if (err >= 0)
		err = erofs_dev_write(sbi, ibuf, erofs_iloc(&oi), ondisk_size);
	free(ibuf);
	return err;
}

struct erofs_inode *erofs_rebuild_make_root(struct erofs_sb_info *sbi)
{
	struct erofs_inode *root;

	root = erofs_new_inode(sbi);
	if (IS_ERR(root))
		return root;
	root->i_srcpath = strdup("/");
	root->i_mode = S_IFDIR | 0777;
	root->i_parent = root;
	root->i_mtime = root->sbi->epoch + root->sbi->build_time;
	root->i_mtime_nsec = root->sbi->fixed_nsec;
	erofs_init_empty_dir(root);
	return root;
}
