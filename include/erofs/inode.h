/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 * with heavy changes by Gao Xiang <xiang@kernel.org>
 */
#ifndef __EROFS_INODE_H
#define __EROFS_INODE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "erofs/internal.h"

#define EROFS_NID_UNALLOCATED	-1ULL

static inline struct erofs_inode *erofs_igrab(struct erofs_inode *inode)
{
	(void)erofs_atomic_inc_return(&inode->i_count);
	return inode;
}

u32 erofs_new_encode_dev(dev_t dev);
unsigned char erofs_mode_to_ftype(umode_t mode);
umode_t erofs_ftype_to_mode(unsigned int ftype, unsigned int perm);
unsigned char erofs_ftype_to_dtype(unsigned int filetype);
void erofs_inode_manager_init(void);
void erofs_insert_ihash(struct erofs_inode *inode);
void erofs_remove_ihash(struct erofs_inode *inode);
struct erofs_inode *erofs_iget(dev_t dev, ino_t ino);
unsigned int erofs_iput(struct erofs_inode *inode);
erofs_nid_t erofs_lookupnid(struct erofs_inode *inode);
int erofs_iflush(struct erofs_inode *inode);
struct erofs_dentry *erofs_d_alloc(struct erofs_inode *parent,
				   const char *name);
int erofs_allocate_inode_bh_data(struct erofs_inode *inode, erofs_blk_t nblocks);
bool erofs_dentry_is_wht(struct erofs_sb_info *sbi, struct erofs_dentry *d);
int erofs_rebuild_dump_tree(struct erofs_inode *dir, bool incremental);
int __erofs_fill_inode(struct erofs_inode *inode, struct stat *st,
		       const char *path);
struct erofs_inode *erofs_new_inode(struct erofs_sb_info *sbi);
struct erofs_inode *erofs_mkfs_build_tree_from_path(struct erofs_sb_info *sbi,
						    const char *path);
struct erofs_inode *erofs_mkfs_build_special_from_fd(struct erofs_sb_info *sbi,
						     int fd, const char *name);
int erofs_fixup_root_inode(struct erofs_inode *root);
struct erofs_inode *erofs_rebuild_make_root(struct erofs_sb_info *sbi);

#ifdef __cplusplus
}
#endif

#endif
