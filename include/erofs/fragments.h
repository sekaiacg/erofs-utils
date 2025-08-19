/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C), 2022, Coolpad Group Limited.
 */
#ifndef __EROFS_FRAGMENTS_H
#define __EROFS_FRAGMENTS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "erofs/internal.h"

extern const char *erofs_frags_packedname;
#define EROFS_PACKED_INODE	erofs_frags_packedname

static inline bool erofs_is_packed_inode(struct erofs_inode *inode)
{
	return inode->i_srcpath == EROFS_PACKED_INODE;
}

struct erofs_importer;

u32 z_erofs_fragments_tofh(struct erofs_inode *inode, int fd, erofs_off_t fpos);
int erofs_fragment_findmatch(struct erofs_inode *inode, int fd, u32 tofh);

int erofs_pack_file_from_fd(struct erofs_inode *inode, int fd, u32 tofcrc);
int erofs_fragment_pack(struct erofs_inode *inode, void *data,
			erofs_off_t pos, erofs_off_t len, u32 tofh, bool tail);
int erofs_fragment_commit(struct erofs_inode *inode, u32 tofh);
int erofs_flush_packed_inode(struct erofs_importer *im);
int erofs_packedfile(struct erofs_sb_info *sbi);

int erofs_packedfile_init(struct erofs_sb_info *sbi, bool fragments_mkfs);
void erofs_packedfile_exit(struct erofs_sb_info *sbi);

int erofs_packedfile_read(struct erofs_sb_info *sbi,
			  void *buf, erofs_off_t len, erofs_off_t pos);

#ifdef __cplusplus
}
#endif

#endif
