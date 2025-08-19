// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2025 Alibaba Cloud
 */
#include "erofs/fragments.h"
#include "erofs/importer.h"
#include "erofs/config.h"
#include "erofs/dedupe.h"
#include "erofs/inode.h"
#include "erofs/print.h"
#include "erofs/lock.h"
#include "liberofs_metabox.h"

static EROFS_DEFINE_MUTEX(erofs_importer_global_mutex);
static bool erofs_importer_global_initialized;

void erofs_importer_preset(struct erofs_importer_params *params)
{
	*params = (struct erofs_importer_params) {
		.fixed_uid = -1,
		.fixed_gid = -1,
	};
}

void erofs_importer_global_init(void)
{
	if (erofs_importer_global_initialized)
		return;
	erofs_mutex_lock(&erofs_importer_global_mutex);
	if (!erofs_importer_global_initialized) {
		erofs_inode_manager_init();
		erofs_importer_global_initialized = true;
	}
	erofs_mutex_unlock(&erofs_importer_global_mutex);
}

int erofs_importer_init(struct erofs_importer *im)
{
	struct erofs_sb_info *sbi = im->sbi;
	const char *subsys = NULL;
	int err;

	erofs_importer_global_init();

	if (cfg.c_fragments || cfg.c_extra_ea_name_prefixes) {
		subsys = "packedfile";
		if (!cfg.c_mkfs_pclustersize_packed)
			cfg.c_mkfs_pclustersize_packed = cfg.c_mkfs_pclustersize_def;

		err = erofs_packedfile_init(sbi, cfg.c_fragments);
		if (err)
			goto out_err;
	}

	if (cfg.c_mkfs_pclustersize_metabox >= 0) {
		subsys = "metabox";
		err = erofs_metabox_init(sbi);
		if (err)
			goto out_err;
	}

	if (cfg.c_fragments) {
		subsys = "dedupe_ext";
		err = z_erofs_dedupe_ext_init();
		if (err)
			goto out_err;
	}
	return 0;

out_err:
	erofs_err("failed to initialize %s: %s", subsys, erofs_strerror(-err));
	return err;
}

void erofs_importer_exit(struct erofs_importer *im)
{
	struct erofs_sb_info *sbi = im->sbi;

	z_erofs_dedupe_ext_exit();
	erofs_metabox_exit(sbi);
	erofs_packedfile_exit(sbi);
}
