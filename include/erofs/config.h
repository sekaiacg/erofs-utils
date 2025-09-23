/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_CONFIG_H
#define __EROFS_CONFIG_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "defs.h"
#include "err.h"

enum {
	FORCE_INODE_BLOCK_MAP = 1,
	FORCE_INODE_CHUNK_INDEXES,
};

enum {
	TIMESTAMP_UNSPECIFIED,
	TIMESTAMP_NONE,
	TIMESTAMP_FIXED,
	TIMESTAMP_CLAMPING,
};

enum {
	FRAGDEDUPE_FULL,
	FRAGDEDUPE_INODE,
	FRAGDEDUPE_OFF,
};

#define EROFS_MAX_COMPR_CFGS		64

struct erofs_compr_opts {
	char *alg;
	int level;
	u32 dict_size;
};

struct erofs_configure {
	const char *c_version;
	int c_dbg_lvl;
	bool c_dry_run;
	bool c_legacy_compress;
	char c_timeinherit;
	char c_chunkbits;
	bool c_ztailpacking;
	bool c_fragments;
	bool c_all_fragments;
	bool c_dedupe;
	char c_fragdedupe;
	bool c_showprogress;
	bool c_extra_ea_name_prefixes;
	bool c_xattr_name_filter;

#ifdef HAVE_LIBSELINUX
	struct selabel_handle *sehnd;
#endif
	/* related arguments for mkfs.erofs */
	char *c_img_path;
	char *c_src_path;
	char *c_blobdev_path;
	char *c_compress_hints_file;
	struct erofs_compr_opts c_compr_opts[EROFS_MAX_COMPR_CFGS];
	char c_force_chunkformat;
	u8 c_mkfs_metabox_algid;
	/* < 0, xattr disabled and INT_MAX, always use inline xattrs */
	int c_inline_xattr_tolerance;
	u32 c_max_decompressed_extent_bytes;
	u64 c_unix_timestamp;
	const char *mount_point;
	u32 c_root_xattr_isize;
#ifdef EROFS_MT_ENABLED
	u64 c_mkfs_segment_size;
	u32 c_mt_workers;
#endif
#ifdef WITH_ANDROID
	char *target_out_path;
	char *fs_config_file;
	char *block_list_file;
#endif
#ifndef NDEBUG
	bool c_random_pclusterblks;
	bool c_random_algorithms;
#endif
};

extern struct erofs_configure cfg;

void erofs_init_configure(void);
void erofs_show_config(void);
void erofs_exit_configure(void);

/* (will be deprecated) temporary helper for updating global the cfg */
struct erofs_configure *erofs_get_configure();

void erofs_set_fs_root(const char *rootdir);
const char *erofs_fspath(const char *fullpath);

#ifdef HAVE_LIBSELINUX
int erofs_selabel_open(const char *file_contexts);
#else
static inline int erofs_selabel_open(const char *file_contexts)
{
	return -EINVAL;
}
#endif

void erofs_update_progressinfo(const char *fmt, ...);
char *erofs_trim_for_progressinfo(const char *str, int placeholder);
unsigned int erofs_get_available_processors(void);

#ifdef __cplusplus
}
#endif

#endif
