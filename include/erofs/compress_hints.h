/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C), 2008-2021, OPPO Mobile Comm Corp., Ltd.
 * Created by Huang Jianan <huangjianan@oppo.com>
 */
#ifndef __EROFS_COMPRESS_HINTS_H
#define __EROFS_COMPRESS_HINTS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>
#include <regex.h>
#include "erofs/importer.h"

struct erofs_compress_hints {
	struct list_head list;

	regex_t reg;
	unsigned int physical_clusterblks;
	unsigned char algorithmtype;
};

bool z_erofs_apply_compress_hints(struct erofs_importer *im,
				  struct erofs_inode *inode);
void erofs_cleanup_compress_hints(void);
int erofs_load_compress_hints(struct erofs_importer *im,
			      struct erofs_sb_info *sbi);

#ifdef __cplusplus
}
#endif

#endif
