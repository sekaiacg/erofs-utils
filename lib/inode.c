// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
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
#include "erofs/inode.h"
#include "erofs/cache.h"
#include "erofs/io.h"
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

unsigned char erofs_ftype_to_dtype(unsigned int filetype)
{
	if (filetype >= EROFS_FT_MAX)
		return DT_UNKNOWN;

	return erofs_dtype_by_ftype[filetype];
}

#define NR_INODE_HASHTABLE	16384

struct list_head inode_hashtable[NR_INODE_HASHTABLE];

void erofs_inode_manager_init(void)
{
	unsigned int i;

	for (i = 0; i < NR_INODE_HASHTABLE; ++i)
		init_list_head(&inode_hashtable[i]);
}

/* get the inode from the (source) inode # */
struct erofs_inode *erofs_iget(dev_t dev, ino_t ino)
{
	struct list_head *head =
		&inode_hashtable[(ino ^ dev) % NR_INODE_HASHTABLE];
	struct erofs_inode *inode;

	list_for_each_entry(inode, head, i_hash)
		if (inode->i_ino[1] == ino && inode->dev == dev)
			return erofs_igrab(inode);
	return NULL;
}

struct erofs_inode *erofs_iget_by_nid(erofs_nid_t nid)
{
	struct list_head *head =
		&inode_hashtable[nid % NR_INODE_HASHTABLE];
	struct erofs_inode *inode;

	list_for_each_entry(inode, head, i_hash)
		if (inode->nid == nid)
			return erofs_igrab(inode);
	return NULL;
}

unsigned int erofs_iput(struct erofs_inode *inode)
{
	struct erofs_dentry *d, *t;

	if (inode->i_count > 1)
		return --inode->i_count;

	list_for_each_entry_safe(d, t, &inode->i_subdirs, d_child)
		free(d);

	if (inode->eof_tailraw)
		free(inode->eof_tailraw);
	list_del(&inode->i_hash);
	if (inode->i_srcpath)
		free(inode->i_srcpath);
	if (inode->with_tmpfile)
		fclose(inode->i_tmpfile);
	else if (inode->i_link)
		free(inode->i_link);
	free(inode);
	return 0;
}

struct erofs_dentry *erofs_d_alloc(struct erofs_inode *parent,
				   const char *name)
{
	struct erofs_dentry *d = malloc(sizeof(*d));

	if (!d)
		return ERR_PTR(-ENOMEM);

	strncpy(d->name, name, EROFS_NAME_LEN - 1);
	d->name[EROFS_NAME_LEN - 1] = '\0';

	list_add_tail(&d->d_child, &parent->i_subdirs);
	return d;
}

/* allocate main data for a inode */
static int __allocate_inode_bh_data(struct erofs_inode *inode,
				    unsigned long nblocks,
				    int type)
{
	struct erofs_buffer_head *bh;
	int ret;

	if (!nblocks) {
		/* it has only tail-end data */
		inode->u.i_blkaddr = NULL_ADDR;
		return 0;
	}

	/* allocate main data buffer */
	bh = erofs_balloc(type, erofs_pos(nblocks), 0, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);

	bh->op = &erofs_skip_write_bhops;
	inode->bh_data = bh;

	/* get blkaddr of the bh */
	ret = erofs_mapbh(bh->block);
	DBG_BUGON(ret < 0);

	/* write blocks except for the tail-end block */
	inode->u.i_blkaddr = bh->block->blkaddr;
	return 0;
}

static int comp_subdir(const void *a, const void *b)
{
	const struct erofs_dentry *da, *db;

	da = *((const struct erofs_dentry **)a);
	db = *((const struct erofs_dentry **)b);
	return strcmp(da->name, db->name);
}

static int erofs_prepare_dir_layout(struct erofs_inode *dir,
				    unsigned int nr_subdirs)
{
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
		int len = strlen(d->name) + sizeof(struct erofs_dirent);

		if ((d_size & (erofs_blksiz() - 1)) + len > erofs_blksiz())
			d_size = round_up(d_size, erofs_blksiz());
		d_size += len;
	}
	dir->i_size = d_size;

	/* no compression for all dirs */
	dir->datalayout = EROFS_INODE_FLAT_INLINE;

	/* it will be used in erofs_prepare_inode_buffer */
	dir->idata_size = d_size % erofs_blksiz();
	return 0;
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
	d->inode = erofs_igrab(dir->i_parent);
	d->type = EROFS_FT_DIR;
	return 0;
}

int erofs_prepare_dir_file(struct erofs_inode *dir, unsigned int nr_subdirs)
{
	int ret;

	ret = erofs_init_empty_dir(dir);
	if (ret)
		return ret;

	/* sort subdirs */
	nr_subdirs += 2;
	return erofs_prepare_dir_layout(dir, nr_subdirs);
}

static void fill_dirblock(char *buf, unsigned int size, unsigned int q,
			  struct erofs_dentry *head, struct erofs_dentry *end)
{
	unsigned int p = 0;

	/* write out all erofs_dirents + filenames */
	while (head != end) {
		const unsigned int namelen = strlen(head->name);
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

static int write_dirblock(unsigned int q, struct erofs_dentry *head,
			  struct erofs_dentry *end, erofs_blk_t blkaddr)
{
	char buf[EROFS_MAX_BLOCK_SIZE];

	fill_dirblock(buf, erofs_blksiz(), q, head, end);
	return blk_write(buf, blkaddr, 1);
}

erofs_nid_t erofs_lookupnid(struct erofs_inode *inode)
{
	struct erofs_buffer_head *const bh = inode->bh;
	erofs_off_t off, meta_offset;

	if (!bh || (long long)inode->nid > 0)
		return inode->nid;

	erofs_mapbh(bh->block);
	off = erofs_btell(bh, false);

	meta_offset = erofs_pos(sbi.meta_blkaddr);
	DBG_BUGON(off < meta_offset);
	inode->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
	erofs_dbg("Assign nid %llu to file %s (mode %05o)",
		  inode->nid, inode->i_srcpath, inode->i_mode);
	return inode->nid;
}

static void erofs_d_invalidate(struct erofs_dentry *d)
{
	struct erofs_inode *const inode = d->inode;

	d->nid = erofs_lookupnid(inode);
	erofs_iput(inode);
}

static int erofs_write_dir_file(struct erofs_inode *dir)
{
	struct erofs_dentry *head = list_first_entry(&dir->i_subdirs,
						     struct erofs_dentry,
						     d_child);
	struct erofs_dentry *d;
	int ret;
	unsigned int q, used, blkno;

	q = used = blkno = 0;

	/* allocate dir main data */
	ret = __allocate_inode_bh_data(dir, erofs_blknr(dir->i_size), DIRA);
	if (ret)
		return ret;

	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		const unsigned int len = strlen(d->name) +
			sizeof(struct erofs_dirent);

		erofs_d_invalidate(d);
		if (used + len > erofs_blksiz()) {
			ret = write_dirblock(q, head, d,
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

	DBG_BUGON(used > erofs_blksiz());
	if (used == erofs_blksiz()) {
		DBG_BUGON(dir->i_size % erofs_blksiz());
		DBG_BUGON(dir->idata_size);
		return write_dirblock(q, head, d, dir->u.i_blkaddr + blkno);
	}
	DBG_BUGON(used != dir->i_size % erofs_blksiz());
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
	const unsigned int nblocks = erofs_blknr(inode->i_size);
	int ret;

	inode->datalayout = EROFS_INODE_FLAT_INLINE;

	ret = __allocate_inode_bh_data(inode, nblocks, DATA);
	if (ret)
		return ret;

	if (nblocks)
		blk_write(buf, inode->u.i_blkaddr, nblocks);
	inode->idata_size = inode->i_size % erofs_blksiz();
	if (inode->idata_size) {
		inode->idata = malloc(inode->idata_size);
		if (!inode->idata)
			return -ENOMEM;
		memcpy(inode->idata, buf + erofs_pos(nblocks),
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
	int ret;
	unsigned int nblocks, i;

	inode->datalayout = EROFS_INODE_FLAT_INLINE;
	nblocks = inode->i_size / erofs_blksiz();

	ret = __allocate_inode_bh_data(inode, nblocks, DATA);
	if (ret)
		return ret;

	for (i = 0; i < nblocks; ++i) {
		char buf[EROFS_MAX_BLOCK_SIZE];

		ret = read(fd, buf, erofs_blksiz());
		if (ret != erofs_blksiz()) {
			if (ret < 0)
				return -errno;
			return -EAGAIN;
		}

		ret = blk_write(buf, inode->u.i_blkaddr + i, 1);
		if (ret)
			return ret;
	}

	/* read the tail-end data */
	inode->idata_size = inode->i_size % erofs_blksiz();
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
	erofs_droid_blocklist_write(inode, inode->u.i_blkaddr, nblocks);
	return 0;
}

int erofs_write_file(struct erofs_inode *inode, int fd)
{
	int ret;

	if (!inode->i_size)
		return 0;

	if (cfg.c_chunkbits) {
		inode->u.chunkbits = cfg.c_chunkbits;
		/* chunk indexes when explicitly specified */
		inode->u.chunkformat = 0;
		if (cfg.c_force_chunkformat == FORCE_INODE_CHUNK_INDEXES)
			inode->u.chunkformat = EROFS_CHUNK_FORMAT_INDEXES;
		return erofs_blob_write_chunked_file(inode, fd);
	}

	if (cfg.c_compr_alg[0] && erofs_file_is_compressible(inode)) {
		ret = erofs_write_compressed_file(inode, fd);
		if (!ret || ret != -ENOSPC)
			return ret;

		ret = lseek(fd, 0, SEEK_SET);
		if (ret < 0)
			return -errno;
	}

	/* fallback to all data uncompressed */
	return write_uncompressed_file_from_fd(inode, fd);
}

static bool erofs_bh_flush_write_inode(struct erofs_buffer_head *bh)
{
	struct erofs_inode *const inode = bh->fsprivate;
	const u16 icount = EROFS_INODE_XATTR_ICOUNT(inode->xattr_isize);
	erofs_off_t off = erofs_btell(bh, false);
	union {
		struct erofs_inode_compact dic;
		struct erofs_inode_extended die;
	} u = { {0}, };
	int ret;

	switch (inode->inode_isize) {
	case sizeof(struct erofs_inode_compact):
		u.dic.i_format = cpu_to_le16(0 | (inode->datalayout << 1));
		u.dic.i_xattr_icount = cpu_to_le16(icount);
		u.dic.i_mode = cpu_to_le16(inode->i_mode);
		u.dic.i_nlink = cpu_to_le16(inode->i_nlink);
		u.dic.i_size = cpu_to_le32((u32)inode->i_size);

		u.dic.i_ino = cpu_to_le32(inode->i_ino[0]);

		u.dic.i_uid = cpu_to_le16((u16)inode->i_uid);
		u.dic.i_gid = cpu_to_le16((u16)inode->i_gid);

		switch (inode->i_mode & S_IFMT) {
		case S_IFCHR:
		case S_IFBLK:
		case S_IFIFO:
		case S_IFSOCK:
			u.dic.i_u.rdev = cpu_to_le32(inode->u.i_rdev);
			break;

		default:
			if (is_inode_layout_compression(inode))
				u.dic.i_u.compressed_blocks =
					cpu_to_le32(inode->u.i_blocks);
			else if (inode->datalayout ==
					EROFS_INODE_CHUNK_BASED)
				u.dic.i_u.c.format =
					cpu_to_le16(inode->u.chunkformat);
			else
				u.dic.i_u.raw_blkaddr =
					cpu_to_le32(inode->u.i_blkaddr);
			break;
		}
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

		switch (inode->i_mode & S_IFMT) {
		case S_IFCHR:
		case S_IFBLK:
		case S_IFIFO:
		case S_IFSOCK:
			u.die.i_u.rdev = cpu_to_le32(inode->u.i_rdev);
			break;

		default:
			if (is_inode_layout_compression(inode))
				u.die.i_u.compressed_blocks =
					cpu_to_le32(inode->u.i_blocks);
			else if (inode->datalayout ==
					EROFS_INODE_CHUNK_BASED)
				u.die.i_u.c.format =
					cpu_to_le16(inode->u.chunkformat);
			else
				u.die.i_u.raw_blkaddr =
					cpu_to_le32(inode->u.i_blkaddr);
			break;
		}
		break;
	default:
		erofs_err("unsupported on-disk inode version of nid %llu",
			  (unsigned long long)inode->nid);
		BUG_ON(1);
	}

	ret = dev_write(&u, off, inode->inode_isize);
	if (ret)
		return false;
	off += inode->inode_isize;

	if (inode->xattr_isize) {
		char *xattrs = erofs_export_xattr_ibody(&inode->i_xattrs,
							inode->xattr_isize);
		if (IS_ERR(xattrs))
			return false;

		ret = dev_write(xattrs, off, inode->xattr_isize);
		free(xattrs);
		if (ret)
			return false;

		off += inode->xattr_isize;
	}

	if (inode->extent_isize) {
		if (inode->datalayout == EROFS_INODE_CHUNK_BASED) {
			ret = erofs_blob_write_chunk_indexes(inode, off);
			if (ret)
				return false;
		} else {
			/* write compression metadata */
			off = roundup(off, 8);
			ret = dev_write(inode->compressmeta, off,
					inode->extent_isize);
			if (ret)
				return false;
			free(inode->compressmeta);
		}
	}

	inode->bh = NULL;
	erofs_iput(inode);
	return erofs_bh_flush_generic_end(bh);
}

static struct erofs_bhops erofs_write_inode_bhops = {
	.flush = erofs_bh_flush_write_inode,
};

static int erofs_prepare_tail_block(struct erofs_inode *inode)
{
	struct erofs_buffer_head *bh;
	int ret;

	if (!inode->idata_size)
		return 0;

	bh = inode->bh_data;
	if (bh) {
		/* expend a block as the tail block (should be successful) */
		ret = erofs_bh_balloon(bh, erofs_blksiz());
		if (ret != erofs_blksiz()) {
			DBG_BUGON(1);
			return -EIO;
		}
	} else {
		inode->lazy_tailblock = true;
	}
	return 0;
}

static int erofs_prepare_inode_buffer(struct erofs_inode *inode)
{
	unsigned int inodesize;
	struct erofs_buffer_head *bh, *ibh;

	DBG_BUGON(inode->bh || inode->bh_inline);

	inodesize = inode->inode_isize + inode->xattr_isize;
	if (inode->extent_isize)
		inodesize = roundup(inodesize, 8) + inode->extent_isize;

	/* TODO: tailpacking inline of chunk-based format isn't finalized */
	if (inode->datalayout == EROFS_INODE_CHUNK_BASED)
		goto noinline;

	if (!is_inode_layout_compression(inode)) {
		if (cfg.c_noinline_data && S_ISREG(inode->i_mode)) {
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

	bh = erofs_balloc(INODE, inodesize, 0, inode->idata_size);
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
		bh = erofs_balloc(INODE, inodesize, 0, 0);
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
			erofs_sb_set_ztailpacking();
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
	return 0;
}

static bool erofs_bh_flush_write_inline(struct erofs_buffer_head *bh)
{
	struct erofs_inode *const inode = bh->fsprivate;
	const erofs_off_t off = erofs_btell(bh, false);
	int ret;

	ret = dev_write(inode->idata, off, inode->idata_size);
	if (ret)
		return false;

	inode->idata_size = 0;
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
	struct erofs_buffer_head *bh, *ibh;

	bh = inode->bh_data;

	if (!inode->idata_size)
		goto out;

	/* have enough room to inline data */
	if (inode->bh_inline) {
		ibh = inode->bh_inline;

		ibh->fsprivate = erofs_igrab(inode);
		ibh->op = &erofs_write_inline_bhops;

		erofs_droid_blocklist_write_tail_end(inode, NULL_ADDR);
	} else {
		int ret;
		erofs_off_t pos, zero_pos;

		if (!bh) {
			bh = erofs_balloc(DATA, erofs_blksiz(), 0, 0);
			if (IS_ERR(bh))
				return PTR_ERR(bh);
			bh->op = &erofs_skip_write_bhops;

			/* get blkaddr of bh */
			ret = erofs_mapbh(bh->block);
			inode->u.i_blkaddr = bh->block->blkaddr;
			inode->bh_data = bh;
		} else {
			if (inode->lazy_tailblock) {
				/* expend a tail block (should be successful) */
				ret = erofs_bh_balloon(bh, erofs_blksiz());
				if (ret != erofs_blksiz()) {
					DBG_BUGON(1);
					return -EIO;
				}
				inode->lazy_tailblock = false;
			}
			ret = erofs_mapbh(bh->block);
		}
		DBG_BUGON(ret < 0);
		pos = erofs_btell(bh, true) - erofs_blksiz();

		/* 0'ed data should be padded at head for 0padding conversion */
		if (erofs_sb_has_lz4_0padding() && inode->compressed_idata) {
			zero_pos = pos;
			pos += erofs_blksiz() - inode->idata_size;
		} else {
			/* pad 0'ed data for the other cases */
			zero_pos = pos + inode->idata_size;
		}
		ret = dev_write(inode->idata, pos, inode->idata_size);
		if (ret)
			return ret;

		DBG_BUGON(inode->idata_size > erofs_blksiz());
		if (inode->idata_size < erofs_blksiz()) {
			ret = dev_fillzero(zero_pos,
					   erofs_blksiz() - inode->idata_size,
					   false);
			if (ret)
				return ret;
		}
		inode->idata_size = 0;
		free(inode->idata);
		inode->idata = NULL;

		erofs_droid_blocklist_write_tail_end(inode, erofs_blknr(pos));
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

static bool erofs_should_use_inode_extended(struct erofs_inode *inode)
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
	if ((inode->i_mtime != sbi.build_time ||
	     inode->i_mtime_nsec != sbi.build_time_nsec) &&
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

static int erofs_fill_inode(struct erofs_inode *inode, struct stat *st,
			    const char *path)
{
	int err = erofs_droid_inode_fsconfig(inode, st, path);

	if (err)
		return err;
	inode->i_mode = st->st_mode;
	inode->i_uid = cfg.c_uid == -1 ? st->st_uid : cfg.c_uid;
	inode->i_gid = cfg.c_gid == -1 ? st->st_gid : cfg.c_gid;

	if (inode->i_uid + cfg.c_uid_offset < 0)
		erofs_err("uid overflow @ %s", path);
	inode->i_uid += cfg.c_uid_offset;

	if (inode->i_gid + cfg.c_gid_offset < 0)
		erofs_err("gid overflow @ %s", path);
	inode->i_gid += cfg.c_gid_offset;

	inode->i_mtime = st->st_mtime;
	inode->i_mtime_nsec = ST_MTIM_NSEC(st);

	switch (cfg.c_timeinherit) {
	case TIMESTAMP_CLAMPING:
		if (inode->i_mtime < sbi.build_time)
			break;
	case TIMESTAMP_FIXED:
		inode->i_mtime = sbi.build_time;
		inode->i_mtime_nsec = sbi.build_time_nsec;
	default:
		break;
	}
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

	if (!S_ISDIR(inode->i_mode)) {
		inode->dev = st->st_dev;
		inode->i_ino[1] = st->st_ino;
	}

	if (erofs_should_use_inode_extended(inode)) {
		if (cfg.c_force_inodeversion == FORCE_INODE_COMPACT) {
			erofs_err("file %s cannot be in compact form",
				  inode->i_srcpath);
			return -EINVAL;
		}
		inode->inode_isize = sizeof(struct erofs_inode_extended);
	} else {
		inode->inode_isize = sizeof(struct erofs_inode_compact);
	}

	list_add(&inode->i_hash,
		 &inode_hashtable[(st->st_ino ^ st->st_dev) %
				  NR_INODE_HASHTABLE]);
	return 0;
}

struct erofs_inode *erofs_new_inode(void)
{
	struct erofs_inode *inode;

	inode = calloc(1, sizeof(struct erofs_inode));
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_ino[0] = sbi.inos++;	/* inode serial number */
	inode->i_count = 1;
	inode->datalayout = EROFS_INODE_FLAT_PLAIN;

	init_list_head(&inode->i_hash);
	init_list_head(&inode->i_subdirs);
	init_list_head(&inode->i_xattrs);
	return inode;
}

/* get the inode from the (source) path */
static struct erofs_inode *erofs_iget_from_path(const char *path, bool is_src)
{
	struct stat st;
	struct erofs_inode *inode;
	int ret;

	/* currently, only source path is supported */
	if (!is_src)
		return ERR_PTR(-EINVAL);

	ret = lstat(path, &st);
	if (ret)
		return ERR_PTR(-errno);

	/*
	 * lookup in hash table first, if it already exists we have a
	 * hard-link, just return it. Also don't lookup for directories
	 * since hard-link directory isn't allowed.
	 */
	if (!S_ISDIR(st.st_mode)) {
		inode = erofs_iget(st.st_dev, st.st_ino);
		if (inode)
			return inode;
	}

	/* cannot find in the inode cache */
	inode = erofs_new_inode();
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
	erofs_off_t off, meta_offset;

	erofs_mapbh(bh->block);
	off = erofs_btell(bh, false);

	if (off > rootnid_maxoffset)
		meta_offset = round_up(off - rootnid_maxoffset, erofs_blksiz());
	else
		meta_offset = 0;
	sbi.meta_blkaddr = erofs_blknr(meta_offset);
	rootdir->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
}

static int erofs_mkfs_build_tree(struct erofs_inode *dir, struct list_head *dirs)
{
	int ret;
	DIR *_dir;
	struct dirent *dp;
	struct erofs_dentry *d;
	unsigned int nr_subdirs, i_nlink;

	ret = erofs_scan_file_xattrs(dir);
	if (ret < 0)
		return ret;

	ret = erofs_prepare_xattr_ibody(dir);
	if (ret < 0)
		return ret;

	if (!S_ISDIR(dir->i_mode)) {
		if (S_ISLNK(dir->i_mode)) {
			char *const symlink = malloc(dir->i_size);

			if (!symlink)
				return -ENOMEM;
			ret = readlink(dir->i_srcpath, symlink, dir->i_size);
			if (ret < 0) {
				free(symlink);
				return -errno;
			}
			ret = erofs_write_file_from_buffer(dir, symlink);
			free(symlink);
		} else if (dir->i_size) {
			int fd = open(dir->i_srcpath, O_RDONLY | O_BINARY);
			if (fd < 0)
				return -errno;

			ret = erofs_write_file(dir, fd);
			close(fd);
		} else {
			ret = 0;
		}
		if (ret)
			return ret;

		erofs_prepare_inode_buffer(dir);
		erofs_write_tail_end(dir);
		return 0;
	}

	_dir = opendir(dir->i_srcpath);
	if (!_dir) {
		erofs_err("failed to opendir at %s: %s",
			  dir->i_srcpath, erofs_strerror(errno));
		return -errno;
	}

	nr_subdirs = 0;
	while (1) {
		/*
		 * set errno to 0 before calling readdir() in order to
		 * distinguish end of stream and from an error.
		 */
		errno = 0;
		dp = readdir(_dir);
		if (!dp)
			break;

#ifndef __APPLE__
		if (is_dot_dotdot(dp->d_name))
#else
		if (is_dot_dotdot(dp->d_name) ||
			!strncmp(dp->d_name, ".DS_Store", 9))
#endif
			continue;

		/* skip if it's a exclude file */
		if (erofs_is_exclude_path(dir->i_srcpath, dp->d_name))
			continue;

		d = erofs_d_alloc(dir, dp->d_name);
		if (IS_ERR(d)) {
			ret = PTR_ERR(d);
			goto err_closedir;
		}
		nr_subdirs++;
	}

	if (errno) {
		ret = -errno;
		goto err_closedir;
	}
	closedir(_dir);

	ret = erofs_prepare_dir_file(dir, nr_subdirs);
	if (ret)
		return ret;

	ret = erofs_prepare_inode_buffer(dir);
	if (ret)
		return ret;
	dir->bh->op = &erofs_skip_write_bhops;

	if (IS_ROOT(dir))
		erofs_fixup_meta_blkaddr(dir);

	i_nlink = 0;
	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		char buf[PATH_MAX];
		unsigned char ftype;
		struct erofs_inode *inode;

		if (is_dot_dotdot(d->name)) {
			++i_nlink;
			continue;
		}

		ret = snprintf(buf, PATH_MAX, "%s/%s",
			       dir->i_srcpath, d->name);
		if (ret < 0 || ret >= PATH_MAX) {
			/* ignore the too long path */
			goto fail;
		}

		inode = erofs_iget_from_path(buf, true);

		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
fail:
			d->inode = NULL;
			d->type = EROFS_FT_UNKNOWN;
			return ret;
		}

		/* a hardlink to the existed inode */
		if (inode->i_parent) {
			++inode->i_nlink;
		} else {
			inode->i_parent = dir;
			erofs_igrab(inode);
			list_add_tail(&inode->i_subdirs, dirs);
			++dir->subdirs_queued;
		}
		ftype = erofs_mode_to_ftype(inode->i_mode);
		i_nlink += (ftype == EROFS_FT_DIR);
		d->inode = inode;
		d->type = ftype;
		erofs_info("file %s/%s dumped (type %u)",
			   dir->i_srcpath, d->name, d->type);
	}
	/*
	 * if there're too many subdirs as compact form, set nlink=1
	 * rather than upgrade to use extented form instead.
	 */
	if (i_nlink > USHRT_MAX &&
	    dir->inode_isize == sizeof(struct erofs_inode_compact))
		dir->i_nlink = 1;
	else
		dir->i_nlink = i_nlink;
	return 0;

err_closedir:
	closedir(_dir);
	return ret;
}

static void erofs_mkfs_dump_directory(struct erofs_inode *dir)
{
	erofs_write_dir_file(dir);
	erofs_write_tail_end(dir);
	dir->bh->op = &erofs_write_inode_bhops;
}

struct erofs_inode *erofs_mkfs_build_tree_from_path(const char *path)
{
	LIST_HEAD(dirs);
	struct erofs_inode *inode, *root, *parent;

	root = erofs_igrab(erofs_iget_from_path(path, true));
	if (IS_ERR(root))
		return root;

	root->i_parent = root;	/* rootdir mark */
	root->subdirs_queued = 1;
	list_add(&root->i_subdirs, &dirs);

	do {
		int err;
		char *trimmed;

		inode = list_first_entry(&dirs, struct erofs_inode, i_subdirs);
		list_del(&inode->i_subdirs);
		init_list_head(&inode->i_subdirs);

		trimmed = erofs_trim_for_progressinfo(
				erofs_fspath(inode->i_srcpath),
				sizeof("Processing  ...") - 1);
		erofs_update_progressinfo("Processing %s ...", trimmed);
		free(trimmed);

		err = erofs_mkfs_build_tree(inode, &dirs);
		if (err) {
			root = ERR_PTR(err);
			break;
		}
		parent = inode->i_parent;

		DBG_BUGON(!parent->subdirs_queued);
		if (S_ISDIR(inode->i_mode) && !inode->subdirs_queued)
			erofs_mkfs_dump_directory(inode);
		if (!--parent->subdirs_queued)
			erofs_mkfs_dump_directory(parent);
		erofs_iput(inode);
	} while (!list_empty(&dirs));
	return root;
}

struct erofs_inode *erofs_mkfs_build_special_from_fd(int fd, const char *name)
{
	struct stat st;
	struct erofs_inode *inode;
	int ret;

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0)
		return ERR_PTR(-errno);

	ret = fstat(fd, &st);
	if (ret)
		return ERR_PTR(-errno);

	inode = erofs_new_inode();
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
		sbi.packed_nid = EROFS_PACKED_NID_UNALLOCATED;
		inode->nid = sbi.packed_nid;
	}

	ret = erofs_write_compressed_file(inode, fd);
	if (ret == -ENOSPC) {
		ret = lseek(fd, 0, SEEK_SET);
		if (ret < 0)
			return ERR_PTR(-errno);

		ret = write_uncompressed_file_from_fd(inode, fd);
	}

	if (ret) {
		DBG_BUGON(ret == -ENOSPC);
		return ERR_PTR(ret);
	}
	erofs_prepare_inode_buffer(inode);
	erofs_write_tail_end(inode);
	return inode;
}

int tarerofs_dump_tree(struct erofs_inode *dir)
{
	struct erofs_dentry *d;
	unsigned int nr_subdirs;
	int ret;

	if (erofs_should_use_inode_extended(dir)) {
		if (cfg.c_force_inodeversion == FORCE_INODE_COMPACT) {
			erofs_err("file %s cannot be in compact form",
				  dir->i_srcpath);
			return -EINVAL;
		}
		dir->inode_isize = sizeof(struct erofs_inode_extended);
	} else {
		dir->inode_isize = sizeof(struct erofs_inode_compact);
	}

	ret = erofs_prepare_xattr_ibody(dir);
	if (ret < 0)
		return ret;

	if (!S_ISDIR(dir->i_mode)) {
		if (dir->bh)
			return 0;
		if (S_ISLNK(dir->i_mode)) {
			ret = erofs_write_file_from_buffer(dir, dir->i_link);
			free(dir->i_link);
			dir->i_link = NULL;
		} else if (dir->i_tmpfile) {
			ret = erofs_write_file(dir, fileno(dir->i_tmpfile));
			fclose(dir->i_tmpfile);
			dir->i_tmpfile = NULL;
			dir->with_tmpfile = false;
		} else {
			ret = 0;
		}
		if (ret)
			return ret;
		ret = erofs_prepare_inode_buffer(dir);
		if (ret)
			return ret;
		erofs_write_tail_end(dir);
		return 0;
	}

	nr_subdirs = 0;
	list_for_each_entry(d, &dir->i_subdirs, d_child)
		++nr_subdirs;

	ret = erofs_prepare_dir_layout(dir, nr_subdirs);
	if (ret)
		return ret;

	ret = erofs_prepare_inode_buffer(dir);
	if (ret)
		return ret;
	dir->bh->op = &erofs_skip_write_bhops;

	if (IS_ROOT(dir))
		erofs_fixup_meta_blkaddr(dir);

	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		struct erofs_inode *inode;

		if (is_dot_dotdot(d->name))
			continue;

		inode = erofs_igrab(d->inode);
		ret = tarerofs_dump_tree(inode);
		dir->i_nlink += (erofs_mode_to_ftype(inode->i_mode) == EROFS_FT_DIR);
		erofs_iput(inode);
		if (ret)
			return ret;
	}
	erofs_write_dir_file(dir);
	erofs_write_tail_end(dir);
	dir->bh->op = &erofs_write_inode_bhops;
	return 0;
}
