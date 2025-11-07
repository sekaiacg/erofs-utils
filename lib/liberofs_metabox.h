/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_LIB_LIBEROFS_METABOX_H
#define __EROFS_LIB_LIBEROFS_METABOX_H

#include "erofs/internal.h"

#define EROFS_META_NEW_ADDR	((u32)-1ULL)

extern const char *erofs_metabox_identifier;
#define EROFS_METABOX_INODE	erofs_metabox_identifier

static inline bool erofs_is_metabox_inode(struct erofs_inode *inode)
{
	return inode->i_srcpath == EROFS_METABOX_INODE;
}

static inline bool erofs_has_meta_zone(struct erofs_sb_info *sbi)
{
	return sbi->m2gr || sbi->meta_blkaddr == EROFS_META_NEW_ADDR;
}

struct erofs_importer;

void erofs_metadata_exit(struct erofs_sb_info *sbi);
int erofs_metadata_init(struct erofs_sb_info *sbi);
struct erofs_bufmgr *erofs_metadata_bmgr(struct erofs_sb_info *sbi, bool mbox);
int erofs_metabox_iflush(struct erofs_importer *im);
int erofs_metazone_flush(struct erofs_sb_info *sbi);

#endif
