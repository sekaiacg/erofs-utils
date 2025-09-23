/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Copyright (C) 2025 Alibaba Cloud
 */
#ifndef __EROFS_LIB_LIBEROFS_COMPRESS_H
#define __EROFS_LIB_LIBEROFS_COMPRESS_H

#include "erofs/importer.h"

#define EROFS_CONFIG_COMPR_MAX_SZ	(4000 * 1024)
#define Z_EROFS_COMPR_QUEUE_SZ		(EROFS_CONFIG_COMPR_MAX_SZ * 2)

struct z_erofs_compress_ictx;

void z_erofs_drop_inline_pcluster(struct erofs_inode *inode);
void *erofs_begin_compressed_file(struct erofs_importer *im,
				  struct erofs_inode *inode, int fd, u64 fpos);
int erofs_write_compressed_file(struct z_erofs_compress_ictx *ictx);

int z_erofs_compress_init(struct erofs_importer *im);
int z_erofs_compress_exit(struct erofs_sb_info *sbi);

int z_erofs_mt_global_exit(void);

#endif
