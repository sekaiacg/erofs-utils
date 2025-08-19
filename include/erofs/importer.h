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

struct erofs_importer_params {
};

struct erofs_importer {
	struct erofs_importer_params *params;
	struct erofs_sb_info *sbi;
};

void erofs_importer_preset(struct erofs_importer_params *params);
int erofs_importer_init(struct erofs_importer *im);
void erofs_importer_exit(struct erofs_importer *im);

#ifdef __cplusplus
}
#endif

#endif
