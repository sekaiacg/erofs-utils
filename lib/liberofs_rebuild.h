/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_LIB_LIBEROFS_REBUILD_H
#define __EROFS_LIB_LIBEROFS_REBUILD_H

#include "erofs/internal.h"

enum erofs_rebuild_datamode {
	EROFS_REBUILD_DATA_BLOB_INDEX,
	EROFS_REBUILD_DATA_RESVSP,
	EROFS_REBUILD_DATA_FULL,
};

struct erofs_dentry *erofs_rebuild_get_dentry(struct erofs_inode *pwd,
		char *path, bool aufs, bool *whout, bool *opq, bool to_head);

int erofs_rebuild_load_tree(struct erofs_inode *root, struct erofs_sb_info *sbi,
			    enum erofs_rebuild_datamode mode);

int erofs_rebuild_load_basedir(struct erofs_inode *dir, u64 *nr_subdirs,
			       unsigned int *i_nlink);
#endif
