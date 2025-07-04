// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021-2022 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Wang Qi <mpiglet@outlook.com>
 *            Guo Xuenan <guoxuenan@huawei.com>
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <sys/stat.h>
#include "erofs/print.h"
#include "erofs/inode.h"
#include "erofs/dir.h"
#include "erofs/compress.h"
#include "erofs/fragments.h"
#include "../lib/liberofs_private.h"
#include "../lib/liberofs_uuid.h"


struct erofsdump_cfg {
	unsigned int totalshow;
	bool show_inode;
	bool show_extent;
	bool show_superblock;
	bool show_statistics;
	bool show_subdirectories;
	bool show_file_content;
	erofs_nid_t nid;
	const char *inode_path;
};
static struct erofsdump_cfg dumpcfg;

static const char chart_format[] = "%-16s	%-11d %8.2f%% |%-50s|\n";
static const char header_format[] = "%-16s %11s %16s |%-50s|\n";
static char *file_types[] = {
	".txt", ".so", ".xml", ".apk",
	".odex", ".vdex", ".oat", ".rc",
	".otf", "others",
};
#define OTHERFILETYPE	ARRAY_SIZE(file_types)
/* (1 << FILE_MAX_SIZE_BITS)KB */
#define	FILE_MAX_SIZE_BITS	16

static const char * const file_category_types[] = {
	[EROFS_FT_UNKNOWN] = "unknown type",
	[EROFS_FT_REG_FILE] = "regular file",
	[EROFS_FT_DIR] = "directory",
	[EROFS_FT_CHRDEV] = "char dev",
	[EROFS_FT_BLKDEV] = "block dev",
	[EROFS_FT_FIFO] = "FIFO file",
	[EROFS_FT_SOCK] = "SOCK file",
	[EROFS_FT_SYMLINK] = "symlink file",
};

struct erofs_statistics {
	unsigned long files;
	unsigned long compressed_files;
	unsigned long uncompressed_files;
	unsigned long files_total_size;
	unsigned long files_total_origin_size;
	double compress_rate;

	/* [statistics] # of files based on inode_info->flags */
	unsigned long file_category_stat[EROFS_FT_MAX];
	/* [statistics] # of files based on file name extensions */
	unsigned int file_type_stat[OTHERFILETYPE];
	/* [statistics] # of files based on the original size of files */
	unsigned int file_original_size[FILE_MAX_SIZE_BITS + 1];
	/* [statistics] # of files based on the compressed size of files */
	unsigned int file_comp_size[FILE_MAX_SIZE_BITS + 1];
};
static struct erofs_statistics stats;

static struct option long_options[] = {
	{"version", no_argument, NULL, 'V'},
	{"help", no_argument, NULL, 'h'},
	{"nid", required_argument, NULL, 2},
	{"device", required_argument, NULL, 3},
	{"path", required_argument, NULL, 4},
	{"ls", no_argument, NULL, 5},
	{"offset", required_argument, NULL, 6},
	{"cat", no_argument, NULL, 7},
	{0, 0, 0, 0},
};

struct erofsdump_feature {
	bool compat;
	u32 flag;
	const char *name;
};

static struct erofsdump_feature feature_lists[] = {
	{ true, EROFS_FEATURE_COMPAT_SB_CHKSUM, "sb_csum" },
	{ true, EROFS_FEATURE_COMPAT_MTIME, "mtime" },
	{ true, EROFS_FEATURE_COMPAT_XATTR_FILTER, "xattr_filter" },
	{ false, EROFS_FEATURE_INCOMPAT_ZERO_PADDING, "0padding" },
	{ false, EROFS_FEATURE_INCOMPAT_COMPR_CFGS, "compr_cfgs" },
	{ false, EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER, "big_pcluster" },
	{ false, EROFS_FEATURE_INCOMPAT_CHUNKED_FILE, "chunked_file" },
	{ false, EROFS_FEATURE_INCOMPAT_DEVICE_TABLE, "device_table" },
	{ false, EROFS_FEATURE_INCOMPAT_ZTAILPACKING, "ztailpacking" },
	{ false, EROFS_FEATURE_INCOMPAT_FRAGMENTS, "fragments" },
	{ false, EROFS_FEATURE_INCOMPAT_DEDUPE, "dedupe" },
	{ false, EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES, "xattr_prefixes" },
	{ false, EROFS_FEATURE_INCOMPAT_48BIT, "48bit" },
};

static int erofsdump_readdir(struct erofs_dir_context *ctx);

static void usage(int argc, char **argv)
{
	//	"         1         2         3         4         5         6         7         8  "
	//	"12345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
	printf(
		"Usage: %s [OPTIONS] IMAGE\n"
		"Dump erofs layout from IMAGE.\n"
		"\n"
		"General options:\n"
		" -V, --version   print the version number of dump.erofs and exit\n"
		" -h, --help      display this help and exit\n"
		"\n"
		" -S              show statistic information of the image\n"
		" -e              show extent info (INODE required)\n"
		" -s              show information about superblock\n"
		" --device=X      specify an extra device to be used together\n"
		" --ls            show directory contents (INODE required)\n"
		" --cat           show file contents (INODE required)\n"
		" --nid=#         show the target inode info of nid #\n"
		" --offset=#      skip # bytes at the beginning of IMAGE\n"
		" --path=X        show the target inode info of path X\n",
		argv[0]);
}

static void erofsdump_print_version(void)
{
	printf("dump.erofs (erofs-utils) %s\n", cfg.c_version);
}

static int erofsdump_parse_options_cfg(int argc, char **argv)
{
	int opt, err;
	char *endptr;

	while ((opt = getopt_long(argc, argv, "SVesh",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'e':
			dumpcfg.show_extent = true;
			++dumpcfg.totalshow;
			break;
		case 's':
			dumpcfg.show_superblock = true;
			++dumpcfg.totalshow;
			break;
		case 'S':
			dumpcfg.show_statistics = true;
			++dumpcfg.totalshow;
			break;
		case 'V':
			erofsdump_print_version();
			exit(0);
		case 2:
			dumpcfg.show_inode = true;
			dumpcfg.nid = (erofs_nid_t)atoll(optarg);
			++dumpcfg.totalshow;
			break;
		case 'h':
			usage(argc, argv);
			exit(0);
		case 3:
			err = erofs_blob_open_ro(&g_sbi, optarg);
			if (err)
				return err;
			++g_sbi.extra_devices;
			break;
		case 4:
			dumpcfg.inode_path = optarg;
			dumpcfg.show_inode = true;
			++dumpcfg.totalshow;
			break;
		case 5:
			dumpcfg.show_subdirectories = true;
			break;
		case 6:
			g_sbi.bdev.offset = strtoull(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid disk offset %s", optarg);
				return -EINVAL;
			}
			break;
		case 7:
			dumpcfg.show_file_content = true;
			break;
		default:
			return -EINVAL;
		}
	}

	if (optind >= argc) {
		erofs_err("missing argument: IMAGE");
		return -EINVAL;
	}

	cfg.c_img_path = strdup(argv[optind++]);
	if (!cfg.c_img_path)
		return -ENOMEM;

	if (optind < argc) {
		erofs_err("unexpected argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	return 0;
}

static int erofsdump_get_occupied_size(struct erofs_inode *inode,
		erofs_off_t *size)
{
	*size = 0;
	switch (inode->datalayout) {
	case EROFS_INODE_FLAT_INLINE:
	case EROFS_INODE_FLAT_PLAIN:
	case EROFS_INODE_CHUNK_BASED:
		stats.uncompressed_files++;
		*size = inode->i_size;
		break;
	case EROFS_INODE_COMPRESSED_FULL:
	case EROFS_INODE_COMPRESSED_COMPACT:
		stats.compressed_files++;
		*size = inode->u.i_blocks * erofs_blksiz(inode->sbi);
		break;
	default:
		erofs_err("unknown datalayout");
		return -ENOTSUP;
	}
	return 0;
}

static void inc_file_extension_count(const char *dname, unsigned int len)
{
	char *postfix = memrchr(dname, '.', len);
	int type;

	if (!postfix) {
		type = OTHERFILETYPE - 1;
	} else {
		for (type = 0; type < OTHERFILETYPE - 1; ++type)
			if (!strncmp(postfix, file_types[type],
				     len - (postfix - dname)))
				break;
	}
	++stats.file_type_stat[type];
}

static void update_file_size_statistics(erofs_off_t size, bool original)
{
	unsigned int *file_size = original ? stats.file_original_size :
				  stats.file_comp_size;
	int size_mark = 0;

	size >>= 10;

	while (size) {
		size >>= 1;
		size_mark++;
	}

	if (size_mark >= FILE_MAX_SIZE_BITS)
		file_size[FILE_MAX_SIZE_BITS]++;
	else
		file_size[size_mark]++;
}

static int erofsdump_ls_dirent_iter(struct erofs_dir_context *ctx)
{
	char fname[EROFS_NAME_LEN + 1];

	strncpy(fname, ctx->dname, ctx->de_namelen);
	fname[ctx->de_namelen] = '\0';
	fprintf(stdout, "%10llu    %u  %s\n",  ctx->de_nid | 0ULL,
		ctx->de_ftype, fname);
	return 0;
}

static int erofsdump_dirent_iter(struct erofs_dir_context *ctx)
{
	/* skip "." and ".." dentry */
	if (ctx->dot_dotdot)
		return 0;

	return erofsdump_readdir(ctx);
}

static int erofsdump_read_packed_inode(void)
{
	int err;
	erofs_off_t occupied_size = 0;
	struct erofs_inode vi = { .sbi = &g_sbi, .nid = g_sbi.packed_nid };

	if (!(erofs_sb_has_fragments(&g_sbi) && g_sbi.packed_nid > 0))
		return 0;

	err = erofs_read_inode_from_disk(&vi);
	if (err) {
		erofs_err("failed to read packed file inode from disk");
		return err;
	}

	err = erofsdump_get_occupied_size(&vi, &occupied_size);
	if (err) {
		erofs_err("failed to get the file size of packed inode");
		return err;
	}

	stats.files_total_size += occupied_size;
	update_file_size_statistics(occupied_size, false);
	return 0;
}

static int erofsdump_readdir(struct erofs_dir_context *ctx)
{
	int err;
	erofs_off_t occupied_size = 0;
	struct erofs_inode vi = { .sbi = &g_sbi, .nid = ctx->de_nid };

	err = erofs_read_inode_from_disk(&vi);
	if (err) {
		erofs_err("failed to read file inode from disk");
		return err;
	}
	stats.files++;
	stats.file_category_stat[erofs_mode_to_ftype(vi.i_mode)]++;

	err = erofsdump_get_occupied_size(&vi, &occupied_size);
	if (err) {
		erofs_err("get file size failed");
		return err;
	}

	if (S_ISREG(vi.i_mode)) {
		stats.files_total_origin_size += vi.i_size;
		inc_file_extension_count(ctx->dname, ctx->de_namelen);
		stats.files_total_size += occupied_size;
		update_file_size_statistics(vi.i_size, true);
		update_file_size_statistics(occupied_size, false);
	}

	/* XXXX: the dir depth should be restricted in order to avoid loops */
	if (S_ISDIR(vi.i_mode)) {
		struct erofs_dir_context nctx = {
			.flags = ctx->dir ? EROFS_READDIR_VALID_PNID : 0,
			.pnid = ctx->dir ? ctx->dir->nid : 0,
			.dir = &vi,
			.cb = erofsdump_dirent_iter,
		};

		return erofs_iterate_dir(&nctx, false);
	}
	return 0;
}

static void erofsdump_show_fileinfo(bool show_extent)
{
	const char *ext_fmt[] = {
		"%4d: %8" PRIu64 "..%8" PRIu64 " | %7" PRIu64 " : %10" PRIu64 "..%10" PRIu64 " | %7" PRIu64 "\n",
		"%4d: %8" PRIu64 "..%8" PRIu64 " | %7" PRIu64 " : %10" PRIu64 "..%10" PRIu64 " | %7" PRIu64 "  # device %u\n"
	};
	int err, i;
	erofs_off_t size;
	u16 access_mode;
	struct erofs_inode inode = { .sbi = &g_sbi, .nid = dumpcfg.nid };
	char path[PATH_MAX];
	char access_mode_str[] = "rwxrwxrwx";
	char timebuf[128] = {0};
	unsigned int extent_count = 0;
	struct erofs_map_blocks map = {
		.index = UINT_MAX,
		.m_la = 0,
	};

	if (dumpcfg.inode_path) {
		err = erofs_ilookup(dumpcfg.inode_path, &inode);
		if (err) {
			erofs_err("read inode failed @ %s", dumpcfg.inode_path);
			return;
		}
	} else {
		err = erofs_read_inode_from_disk(&inode);
		if (err) {
			erofs_err("read inode failed @ nid %llu",
				  inode.nid | 0ULL);
			return;
		}
	}

	err = erofs_get_occupied_size(&inode, &size);
	if (err) {
		erofs_err("get file size failed @ nid %llu", inode.nid | 0ULL);
		return;
	}

	err = erofs_get_pathname(inode.sbi, inode.nid, path, sizeof(path));
	if (err < 0) {
		strncpy(path, "(not found)", sizeof(path) - 1);
		path[sizeof(path) - 1] = '\0';
	}

	strftime(timebuf, sizeof(timebuf),
		 "%Y-%m-%d %H:%M:%S", localtime((time_t *)&inode.i_mtime));
	access_mode = inode.i_mode & 0777;
	for (i = 8; i >= 0; i--)
		if (((access_mode >> i) & 1) == 0)
			access_mode_str[8 - i] = '-';
	fprintf(stdout, "Path : %s\n",
		erofs_is_packed_inode(&inode) ? "(packed file)" : path);
	fprintf(stdout, "Size: %" PRIu64"  On-disk size: %" PRIu64 "  %s\n",
		inode.i_size, size,
		file_category_types[erofs_mode_to_ftype(inode.i_mode)]);
	fprintf(stdout, "NID: %" PRIu64 "   ", inode.nid);
	fprintf(stdout, "Links: %u   ", inode.i_nlink);
	fprintf(stdout, "Layout: %d   Compression ratio: %.2f%%\n",
		inode.datalayout,
		(double)(100 * size) / (double)(inode.i_size));
	fprintf(stdout, "Inode size: %d   ", inode.inode_isize);
	fprintf(stdout,	"Xattr size: %u\n", inode.xattr_isize);
	fprintf(stdout, "Uid: %u   Gid: %u  ", inode.i_uid, inode.i_gid);
	fprintf(stdout, "Access: %04o/%s\n", access_mode, access_mode_str);
	fprintf(stdout, "Timestamp: %s.%09d\n", timebuf, inode.i_mtime_nsec);

	if (dumpcfg.show_subdirectories) {
		struct erofs_dir_context ctx = {
			.flags = EROFS_READDIR_VALID_PNID,
			.pnid = inode.nid,
			.dir = &inode,
			.cb = erofsdump_ls_dirent_iter,
			.de_nid = 0,
			.dname = "",
			.de_namelen = 0,
		};

		fprintf(stdout, "\n       NID TYPE  FILENAME\n");
		err = erofs_iterate_dir(&ctx, false);
		if (err) {
			erofs_err("failed to list directory contents");
			return;
		}
	}

	if (!dumpcfg.show_extent)
		return;

	fprintf(stdout, "\n Ext:   logical offset   |  length :     physical offset    |  length\n");
	while (map.m_la < inode.i_size) {
		struct erofs_map_dev mdev;

		err = erofs_map_blocks(&inode, &map, EROFS_GET_BLOCKS_FIEMAP);
		if (err) {
			erofs_err("failed to get file blocks range");
			return;
		}

		mdev = (struct erofs_map_dev) {
			.m_deviceid = map.m_deviceid,
			.m_pa = map.m_pa,
		};
		err = erofs_map_dev(inode.sbi, &mdev);
		if (err) {
			erofs_err("failed to map device");
			return;
		}

		if (map.m_flags & __EROFS_MAP_FRAGMENT)
			fprintf(stdout, ext_fmt[!!mdev.m_deviceid],
				extent_count++,
				map.m_la, map.m_la + map.m_llen, map.m_llen,
				0, 0, 0, mdev.m_deviceid);
		else
			fprintf(stdout, ext_fmt[!!mdev.m_deviceid],
				extent_count++,
				map.m_la, map.m_la + map.m_llen, map.m_llen,
				mdev.m_pa, mdev.m_pa + map.m_plen, map.m_plen,
				mdev.m_deviceid);
		map.m_la += map.m_llen;
	}
	fprintf(stdout, "%s: %d extents found\n",
		erofs_is_packed_inode(&inode) ? "(packed file)" : path, extent_count);
}

static void erofsdump_filesize_distribution(const char *title,
		unsigned int *file_counts, unsigned int len)
{
	char col1[30];
	unsigned int col2, i, lowerbound, upperbound;
	double col3;
	char col4[400];

	lowerbound = 0;
	upperbound = 1;
	fprintf(stdout, "\n%s file size distribution:\n", title);
	fprintf(stdout, header_format, ">=(KB) .. <(KB) ", "count",
			"ratio", "distribution");
	for (i = 0; i < len; i++) {
		memset(col1, 0, sizeof(col1));
		memset(col4, 0, sizeof(col4));
		if (i == len - 1)
			sprintf(col1, "%6d ..", lowerbound);
		else if (i <= 6)
			sprintf(col1, "%6d .. %-6d", lowerbound, upperbound);
		else

			sprintf(col1, "%6d .. %-6d", lowerbound, upperbound);
		col2 = file_counts[i];
		if (stats.file_category_stat[EROFS_FT_REG_FILE])
			col3 = (double)(100 * col2) /
				stats.file_category_stat[EROFS_FT_REG_FILE];
		else
			col3 = 0.0;
		memset(col4, '#', col3 / 2);
		fprintf(stdout, chart_format, col1, col2, col3, col4);
		lowerbound = upperbound;
		upperbound <<= 1;
	}
}

static void erofsdump_filetype_distribution(char **file_types, unsigned int len)
{
	char col1[30];
	unsigned int col2, i;
	double col3;
	char col4[401];

	fprintf(stdout, "\nFile type distribution:\n");
	fprintf(stdout, header_format, "type", "count", "ratio",
			"distribution");
	for (i = 0; i < len; i++) {
		memset(col1, 0, sizeof(col1));
		memset(col4, 0, sizeof(col4));
		sprintf(col1, "%-17s", file_types[i]);
		col2 = stats.file_type_stat[i];
		if (stats.file_category_stat[EROFS_FT_REG_FILE])
			col3 = (double)(100 * col2) /
				stats.file_category_stat[EROFS_FT_REG_FILE];
		else
			col3 = 0.0;
		memset(col4, '#', col3 / 2);
		fprintf(stdout, chart_format, col1, col2, col3, col4);
	}
}

static void erofsdump_file_statistic(void)
{
	unsigned int i;

	fprintf(stdout, "Filesystem total file count:		%lu\n",
			stats.files);
	for (i = 0; i < EROFS_FT_MAX; i++)
		fprintf(stdout, "Filesystem %s count:		%lu\n",
			file_category_types[i], stats.file_category_stat[i]);

	stats.compress_rate = (double)(100 * stats.files_total_size) /
		(double)(stats.files_total_origin_size);
	fprintf(stdout, "Filesystem compressed files:            %lu\n",
			stats.compressed_files);
	fprintf(stdout, "Filesystem uncompressed files:          %lu\n",
			stats.uncompressed_files);
	fprintf(stdout, "Filesystem total original file size:    %lu Bytes\n",
			stats.files_total_origin_size);
	fprintf(stdout, "Filesystem total file size:             %lu Bytes\n",
			stats.files_total_size);
	fprintf(stdout, "Filesystem compress rate:               %.2f%%\n",
			stats.compress_rate);
}

static void erofsdump_print_statistic(void)
{
	int err;
	struct erofs_dir_context ctx = {
		.flags = 0,
		.pnid = 0,
		.dir = NULL,
		.cb = erofsdump_dirent_iter,
		.de_nid = g_sbi.root_nid,
		.dname = "",
		.de_namelen = 0,
	};

	err = erofsdump_readdir(&ctx);
	if (err) {
		erofs_err("read dir failed");
		return;
	}
	err = erofsdump_read_packed_inode();
	if (err) {
		erofs_err("failed to read packed inode");
		return;
	}
	erofsdump_file_statistic();
	erofsdump_filesize_distribution("Original",
			stats.file_original_size,
			ARRAY_SIZE(stats.file_original_size));
	erofsdump_filesize_distribution("On-disk",
			stats.file_comp_size,
			ARRAY_SIZE(stats.file_comp_size));
	erofsdump_filetype_distribution(file_types, OTHERFILETYPE);
}

static void erofsdump_print_supported_compressors(FILE *f, unsigned int mask)
{
	unsigned int i = 0;
	bool comma = false;
	const char *s;

	while ((s = z_erofs_list_supported_algorithms(i++, &mask)) != NULL) {
		if (*s == '\0')
			continue;
		if (comma)
			fputs(", ", f);
		fputs(s, f);
		comma = true;
	}
	fputc('\n', f);
}

static void erofsdump_show_superblock(void)
{
	time_t time = g_sbi.epoch + g_sbi.build_time;
	char uuid_str[37];
	int i = 0;

	fprintf(stdout, "Filesystem magic number:                      0x%04X\n",
			EROFS_SUPER_MAGIC_V1);
	fprintf(stdout, "Filesystem blocksize:                         %u\n",
			erofs_blksiz(&g_sbi));
	fprintf(stdout, "Filesystem blocks:                            %llu\n",
			g_sbi.total_blocks | 0ULL);
	fprintf(stdout, "Filesystem inode metadata start block:        %u\n",
			g_sbi.meta_blkaddr);
	fprintf(stdout, "Filesystem shared xattr metadata start block: %u\n",
			g_sbi.xattr_blkaddr);
	fprintf(stdout, "Filesystem root nid:                          %llu\n",
			g_sbi.root_nid | 0ULL);
	if (erofs_sb_has_fragments(&g_sbi) && g_sbi.packed_nid > 0)
		fprintf(stdout, "Filesystem packed nid:                        %llu\n",
			g_sbi.packed_nid | 0ULL);
	if (erofs_sb_has_compr_cfgs(&g_sbi)) {
		fprintf(stdout, "Filesystem compr_algs:                        ");
		erofsdump_print_supported_compressors(stdout,
			g_sbi.available_compr_algs);
	} else {
		fprintf(stdout, "Filesystem lz4_max_distance:                  %u\n",
			g_sbi.lz4.max_distance | 0U);
	}
	fprintf(stdout, "Filesystem sb_size:                           %u\n",
			g_sbi.sb_size | 0U);
	fprintf(stdout, "Filesystem inode count:                       %llu\n",
			g_sbi.inos | 0ULL);
	fprintf(stdout, "Filesystem created:                           %s",
			ctime(&time));
	fprintf(stdout, "Filesystem features:                          ");
	for (; i < ARRAY_SIZE(feature_lists); i++) {
		u32 feat = le32_to_cpu(feature_lists[i].compat ?
				       g_sbi.feature_compat :
				       g_sbi.feature_incompat);
		if (feat & feature_lists[i].flag)
			fprintf(stdout, "%s ", feature_lists[i].name);
	}
	erofs_uuid_unparse_lower(g_sbi.uuid, uuid_str);
	fprintf(stdout, "\nFilesystem UUID:                              %s\n",
			uuid_str);
}

static void erofsdump_show_file_content(void)
{
	int err;
	struct erofs_inode inode = { .sbi = &g_sbi, .nid = dumpcfg.nid };
	size_t buffer_size;
	char *buffer_ptr;
	erofs_off_t pending_size;
	erofs_off_t read_offset;
	erofs_off_t read_size;

	if (dumpcfg.inode_path) {
		err = erofs_ilookup(dumpcfg.inode_path, &inode);
		if (err) {
			erofs_err("read inode failed @ %s", dumpcfg.inode_path);
			return;
		}
	} else {
		err = erofs_read_inode_from_disk(&inode);
		if (err) {
			erofs_err("read inode failed @ nid %llu", inode.nid | 0ULL);
			return;
		}
	}

	buffer_size = erofs_blksiz(inode.sbi);
	buffer_ptr = malloc(buffer_size);
	if (!buffer_ptr) {
		erofs_err("buffer allocation failed @ nid %llu", inode.nid | 0ULL);
		return;
	}

	pending_size = inode.i_size;
	read_offset = 0;
	while (pending_size > 0) {
		read_size = pending_size > buffer_size? buffer_size: pending_size;
		err = erofs_pread(&inode, buffer_ptr, read_size, read_offset);
		if (err) {
			erofs_err("read file failed @ nid %llu", inode.nid | 0ULL);
			goto out;
		}
		pending_size -= read_size;
		read_offset += read_size;
		fwrite(buffer_ptr, read_size, 1, stdout);
	}
	fflush(stdout);

out:
	free(buffer_ptr);
}

int main(int argc, char **argv)
{
	int err;

	erofs_init_configure();
	err = erofsdump_parse_options_cfg(argc, argv);
	if (err) {
		if (err == -EINVAL)
			fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		goto exit;
	}

	err = erofs_dev_open(&g_sbi, cfg.c_img_path, O_RDONLY | O_TRUNC);
	if (err) {
		erofs_err("failed to open image file");
		goto exit;
	}

	err = erofs_read_superblock(&g_sbi);
	if (err) {
		erofs_err("failed to read superblock");
		goto exit_dev_close;
	}

	if (dumpcfg.show_file_content) {
		if (dumpcfg.show_superblock || dumpcfg.show_statistics || dumpcfg.show_subdirectories) {
			fprintf(stderr, "The '--cat' flag is incompatible with '-S', '-e', '-s' and '--ls'.\n");
			goto exit_dev_close;
		}
		erofsdump_show_file_content();
		goto exit_dev_close;
	}

	if (!dumpcfg.totalshow) {
		dumpcfg.show_superblock = true;
		dumpcfg.totalshow = 1;
	}
	if (dumpcfg.show_superblock)
		erofsdump_show_superblock();

	if (dumpcfg.show_statistics)
		erofsdump_print_statistic();

	if (dumpcfg.show_extent && !dumpcfg.show_inode) {
		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		goto exit_put_super;
	}

	if (dumpcfg.show_inode)
		erofsdump_show_fileinfo(dumpcfg.show_extent);

exit_put_super:
	erofs_put_super(&g_sbi);
exit_dev_close:
	erofs_dev_close(&g_sbi);
exit:
	erofs_blob_closeall(&g_sbi);
	erofs_exit_configure();
	return err;
}
