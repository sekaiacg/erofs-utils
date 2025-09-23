/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2025 Alibaba Cloud
 */
#ifndef __EROFS_IMPORTER_H
#define __EROFS_IMPORTER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

enum {
	EROFS_FORCE_INODE_COMPACT = 1,
	EROFS_FORCE_INODE_EXTENDED,
};

struct erofs_importer_params {
	char *source;
	u32 mt_async_queue_limit;
	u32 fixed_uid;
	u32 fixed_gid;
	u32 uid_offset;
	u32 gid_offset;
	u32 fsalignblks;
	u32 pclusterblks_max;
	u32 pclusterblks_def;
	u32 pclusterblks_packed;
	s32 pclusterblks_metabox;
	char force_inodeversion;
	bool ignore_mtime;
	bool no_datainline;
	bool hard_dereference;
	bool ovlfs_strip;
	bool dot_omitted;
};

struct erofs_importer {
	struct erofs_importer_params *params;
	struct erofs_sb_info *sbi;
	struct erofs_inode *root;
};

void erofs_importer_preset(struct erofs_importer_params *params);
int erofs_importer_init(struct erofs_importer *im);
int erofs_importer_flush_all(struct erofs_importer *im);
void erofs_importer_exit(struct erofs_importer *im);

#ifdef __cplusplus
}
#endif

#endif
