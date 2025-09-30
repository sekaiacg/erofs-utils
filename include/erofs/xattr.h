/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Originally contributed by an anonymous person,
 * heavily changed by Li Guifu <blucerlee@gmail.com>
 *                and Gao Xiang <xiang@kernel.org>
 */
#ifndef __EROFS_XATTR_H
#define __EROFS_XATTR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

#ifndef ENOATTR
#define ENOATTR	ENODATA
#endif

static inline unsigned int inlinexattr_header_size(struct erofs_inode *vi)
{
	return sizeof(struct erofs_xattr_ibody_header) +
		sizeof(u32) * vi->xattr_shared_count;
}

static inline erofs_blk_t xattrblock_addr(struct erofs_inode *vi,
					  unsigned int xattr_id)
{
	return vi->sbi->xattr_blkaddr +
		erofs_blknr(vi->sbi, xattr_id * sizeof(__u32));
}

static inline unsigned int xattrblock_offset(struct erofs_inode *vi,
					     unsigned int xattr_id)
{
	return erofs_blkoff(vi->sbi, xattr_id * sizeof(__u32));
}

#define EROFS_INODE_XATTR_ICOUNT(_size)	({\
	u32 __size = le16_to_cpu(_size); \
	((__size) == 0) ? 0 : \
	(_size - sizeof(struct erofs_xattr_ibody_header)) / \
	sizeof(struct erofs_xattr_entry) + 1; })

struct erofs_importer;

int erofs_xattr_init(struct erofs_sb_info *sbi);
int erofs_scan_file_xattrs(struct erofs_inode *inode);
int erofs_prepare_xattr_ibody(struct erofs_inode *inode, bool noroom);
char *erofs_export_xattr_ibody(struct erofs_inode *inode);
int erofs_load_shared_xattrs_from_path(struct erofs_sb_info *sbi, const char *path,
				       long inlinexattr_tolerance);
int erofs_xattr_insert_name_prefix(const char *prefix);
void erofs_xattr_cleanup_name_prefixes(void);
int erofs_xattr_flush_name_prefixes(struct erofs_importer *im, bool plain);
int erofs_xattr_prefixes_init(struct erofs_sb_info *sbi);

int erofs_setxattr(struct erofs_inode *inode, char *key,
		   const void *value, size_t size);
int erofs_set_opaque_xattr(struct erofs_inode *inode);
void erofs_clear_opaque_xattr(struct erofs_inode *inode);
int erofs_set_origin_xattr(struct erofs_inode *inode);
int erofs_read_xattrs_from_disk(struct erofs_inode *inode);

bool erofs_xattr_prefix_matches(const char *key, unsigned int *index,
				unsigned int *len);
void erofs_xattr_exit(struct erofs_sb_info *sbi);

#ifdef __cplusplus
}
#endif

#endif
