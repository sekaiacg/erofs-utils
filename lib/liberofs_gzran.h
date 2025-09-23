/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2025 Alibaba Cloud
 */
#ifndef __EROFS_LIB_LIBEROFS_GZRAN_H
#define __EROFS_LIB_LIBEROFS_GZRAN_H

#include "erofs/io.h"

#define EROFS_GZRAN_WINSIZE	32768

struct erofs_gzran_builder;

struct erofs_gzran_builder *erofs_gzran_builder_init(struct erofs_vfile *vf,
						     u32 span_size);
int erofs_gzran_builder_read(struct erofs_gzran_builder *gb, char *window);
int erofs_gzran_builder_export_zinfo(struct erofs_gzran_builder *gb,
				     struct erofs_vfile *zinfo_vf);
int erofs_gzran_builder_final(struct erofs_gzran_builder *gb);

struct erofs_vfile *erofs_gzran_zinfo_open(struct erofs_vfile *vin,
					   void *zinfo_buf, unsigned int len);
#endif
