/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_LIB_LIBEROFS_METABOX_H
#define __EROFS_LIB_LIBEROFS_METABOX_H

#include "erofs/internal.h"

extern const char *erofs_metabox_identifier;
#define EROFS_METABOX_INODE	erofs_metabox_identifier

static inline bool erofs_is_metabox_inode(struct erofs_inode *inode)
{
	return inode->i_srcpath == EROFS_METABOX_INODE;
}

struct erofs_importer;

void erofs_metabox_exit(struct erofs_sb_info *sbi);
int erofs_metabox_init(struct erofs_sb_info *sbi);
struct erofs_bufmgr *erofs_metabox_bmgr(struct erofs_sb_info *sbi);
int erofs_metabox_iflush(struct erofs_importer *im);

#endif
