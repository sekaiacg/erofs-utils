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
#include "liberofs_cache.h"
#include "liberofs_compress.h"
#include "liberofs_metabox.h"

static EROFS_DEFINE_MUTEX(erofs_importer_global_mutex);
static bool erofs_importer_global_initialized;

void erofs_importer_preset(struct erofs_importer_params *params)
{
	*params = (struct erofs_importer_params) {
		.fixed_uid = -1,
		.fixed_gid = -1,
		.fsalignblks = 1,
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
	struct erofs_importer_params *params = im->params;
	const char *subsys = NULL;
	int err;

	erofs_importer_global_init();

	subsys = "compression";
	err = z_erofs_compress_init(im);
	if (err)
		goto out_err;

	if (cfg.c_fragments || cfg.c_extra_ea_name_prefixes) {
		subsys = "packedfile";
		if (!cfg.c_mkfs_pclustersize_packed)
			cfg.c_mkfs_pclustersize_packed = cfg.c_mkfs_pclustersize_def;

		err = erofs_packedfile_init(sbi, cfg.c_fragments);
		if (err)
			goto out_err;
	}

	subsys = "metabox";
	err = erofs_metabox_init(sbi);
	if (err)
		goto out_err;

	if (cfg.c_fragments) {
		subsys = "dedupe_ext";
		err = z_erofs_dedupe_ext_init();
		if (err)
			goto out_err;
	}

	if (params->dot_omitted)
		erofs_sb_set_48bit(sbi);
	return 0;

out_err:
	erofs_err("failed to initialize %s: %s", subsys, erofs_strerror(-err));
	return err;
}

int erofs_importer_flush_all(struct erofs_importer *im)
{
	struct erofs_sb_info *sbi = im->sbi;
	unsigned int fsalignblks;
	int err;

	if (erofs_sb_has_metabox(sbi)) {
		erofs_update_progressinfo("Handling metabox ...");
		err = erofs_metabox_iflush(im);
		if (err)
			return err;
	}

	if ((cfg.c_fragments || cfg.c_extra_ea_name_prefixes) &&
	    erofs_sb_has_fragments(sbi)) {
		erofs_update_progressinfo("Handling packed data ...");
		err = erofs_flush_packed_inode(im);
		if (err)
			return err;
	}

	fsalignblks = im->params->fsalignblks ?
		roundup_pow_of_two(im->params->fsalignblks) : 1;
	sbi->primarydevice_blocks = roundup(erofs_mapbh(sbi->bmgr, NULL),
					    fsalignblks);
	err = erofs_write_device_table(sbi);
	if (err)
		return err;

	/* flush all buffers except for the superblock */
	err = erofs_bflush(sbi->bmgr, NULL);
	if (err)
		return err;

	return erofs_fixup_root_inode(im->root);
}

void erofs_importer_exit(struct erofs_importer *im)
{
	struct erofs_sb_info *sbi = im->sbi;

	z_erofs_dedupe_ext_exit();
	erofs_metabox_exit(sbi);
	erofs_packedfile_exit(sbi);
}
