// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <limits.h>
#include <libgen.h>
#include <sys/stat.h>
#include <getopt.h>
#include "erofs/config.h"
#include "erofs/print.h"
#include "erofs/cache.h"
#include "erofs/diskbuf.h"
#include "erofs/inode.h"
#include "erofs/tar.h"
#include "erofs/io.h"
#include "erofs/compress.h"
#include "erofs/dedupe.h"
#include "erofs/xattr.h"
#include "erofs/exclude.h"
#include "erofs/block_list.h"
#include "erofs/compress_hints.h"
#include "erofs/blobchunk.h"
#include "erofs/fragments.h"
#include "erofs/rebuild.h"
#include "../lib/liberofs_private.h"
#include "../lib/liberofs_uuid.h"
#include "../lib/compressor.h"

#define EROFS_SUPER_END (EROFS_SUPER_OFFSET + sizeof(struct erofs_super_block))

static struct option long_options[] = {
	{"version", no_argument, 0, 'V'},
	{"help", no_argument, 0, 'h'},
	{"exclude-path", required_argument, NULL, 2},
	{"exclude-regex", required_argument, NULL, 3},
#ifdef HAVE_LIBSELINUX
	{"file-contexts", required_argument, NULL, 4},
#endif
	{"force-uid", required_argument, NULL, 5},
	{"force-gid", required_argument, NULL, 6},
	{"all-root", no_argument, NULL, 7},
#ifndef NDEBUG
	{"random-pclusterblks", no_argument, NULL, 8},
	{"random-algorithms", no_argument, NULL, 18},
#endif
	{"max-extent-bytes", required_argument, NULL, 9},
	{"compress-hints", required_argument, NULL, 10},
	{"chunksize", required_argument, NULL, 11},
	{"quiet", no_argument, 0, 12},
	{"blobdev", required_argument, NULL, 13},
	{"ignore-mtime", no_argument, NULL, 14},
	{"preserve-mtime", no_argument, NULL, 15},
	{"uid-offset", required_argument, NULL, 16},
	{"gid-offset", required_argument, NULL, 17},
	{"tar", optional_argument, NULL, 20},
	{"aufs", no_argument, NULL, 21},
	{"mount-point", required_argument, NULL, 512},
	{"xattr-prefix", required_argument, NULL, 19},
#ifdef WITH_ANDROID
	{"product-out", required_argument, NULL, 513},
	{"fs-config-file", required_argument, NULL, 514},
	{"block-list-file", required_argument, NULL, 515},
#endif
	{"ovlfs-strip", optional_argument, NULL, 516},
	{"offset", required_argument, NULL, 517},
#ifdef HAVE_ZLIB
	{"gzip", no_argument, NULL, 518},
	{"ungzip", optional_argument, NULL, 518},
#endif
#ifdef HAVE_LIBLZMA
	{"unlzma", optional_argument, NULL, 519},
	{"unxz", optional_argument, NULL, 519},
#endif
#ifdef EROFS_MT_ENABLED
	{"workers", required_argument, NULL, 520},
#endif
	{0, 0, 0, 0},
};

static void print_available_compressors(FILE *f, const char *delim)
{
	int i = 0;
	bool comma = false;
	const struct erofs_algorithm *s;

	while ((s = z_erofs_list_available_compressors(&i)) != NULL) {
		if (comma)
			fputs(delim, f);
		fputs(s->name, f);
		comma = true;
	}
	fputc('\n', f);
}

static void usage(int argc, char **argv)
{
	int i = 0;
	const struct erofs_algorithm *s;

	//	"         1         2         3         4         5         6         7         8  "
	//	"12345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
	printf(
		"Usage: %s [OPTIONS] FILE SOURCE(s)\n"
		"Generate EROFS image (FILE) from SOURCE(s).\n"
		"\n"
		"General options:\n"
		" -V, --version         print the version number of mkfs.erofs and exit\n"
		" -h, --help            display this help and exit\n"
		"\n"
		" -b#                   set block size to # (# = page size by default)\n"
		" -d<0-9>               set output verbosity; 0=quiet, 9=verbose (default=%i)\n"
		" -x#                   set xattr tolerance to # (< 0, disable xattrs; default 2)\n"
		" -zX[,level=Y]         X=compressor (Y=compression level, Z=dictionary size, optional)\n"
		"    [,dictsize=Z]      alternative compressors can be separated by colons(:)\n"
		"    [:...]             supported compressors and their option ranges are:\n",
		argv[0], EROFS_WARN);
	while ((s = z_erofs_list_available_compressors(&i)) != NULL) {
		const char spaces[] = "                         ";

		printf("%s%s\n", spaces, s->name);
		if (s->c->setlevel) {
			if (!strcmp(s->name, "lzma"))
				/* A little kludge to show the range as disjointed
				 * "0-9,100-109" instead of a continuous "0-109", and to
				 * state what those two subranges respectively mean.  */
				printf("%s  [,level=<0-9,100-109>]\t0-9=normal, 100-109=extreme (default=%i)\n",
				       spaces, s->c->default_level);
			else
				printf("%s  [,level=<0-%i>]\t\t(default=%i)\n",
				       spaces, s->c->best_level, s->c->default_level);
		}
		if (s->c->setdictsize) {
			if (s->c->default_dictsize)
				printf("%s  [,dictsize=<dictsize>]\t(default=%u, max=%u)\n",
				       spaces, s->c->default_dictsize, s->c->max_dictsize);
			else
				printf("%s  [,dictsize=<dictsize>]\t(default=<auto>, max=%u)\n",
				       spaces, s->c->max_dictsize);
		}
	}
	printf(
		" -C#                   specify the size of compress physical cluster in bytes\n"
		" -EX[,...]             X=extended options\n"
		" -L volume-label       set the volume label (maximum 16)\n"
		" -T#                   set a fixed UNIX timestamp # to all files\n"
		" -UX                   use a given filesystem UUID\n"
		" --all-root            make all files owned by root\n"
		" --blobdev=X           specify an extra device X to store chunked data\n"
		" --chunksize=#         generate chunk-based files with #-byte chunks\n"
		" --compress-hints=X    specify a file to configure per-file compression strategy\n"
		" --exclude-path=X      avoid including file X (X = exact literal path)\n"
		" --exclude-regex=X     avoid including files that match X (X = regular expression)\n"
#ifdef HAVE_LIBSELINUX
		" --file-contexts=X     specify a file contexts file to setup selinux labels\n"
#endif
		" --force-uid=#         set all file uids to # (# = UID)\n"
		" --force-gid=#         set all file gids to # (# = GID)\n"
		" --uid-offset=#        add offset # to all file uids (# = id offset)\n"
		" --gid-offset=#        add offset # to all file gids (# = id offset)\n"
		" --ignore-mtime        use build time instead of strict per-file modification time\n"
		" --max-extent-bytes=#  set maximum decompressed extent size # in bytes\n"
		" --preserve-mtime      keep per-file modification time strictly\n"
		" --offset=#            skip # bytes at the beginning of IMAGE.\n"
		" --aufs                replace aufs special files with overlayfs metadata\n"
		" --tar=X               generate a full or index-only image from a tarball(-ish) source\n"
		"                       (X = f|i|headerball; f=full mode, i=index mode,\n"
		"                                            headerball=file data is omited in the source stream)\n"
		" --ovlfs-strip=<0,1>   strip overlayfs metadata in the target image (e.g. whiteouts)\n"
		" --quiet               quiet execution (do not write anything to standard output.)\n"
#ifndef NDEBUG
		" --random-pclusterblks randomize pclusterblks for big pcluster (debugging only)\n"
		" --random-algorithms   randomize per-file algorithms (debugging only)\n"
#endif
#ifdef HAVE_ZLIB
		" --ungzip[=X]          try to filter the tarball stream through gzip\n"
		"                       (and optionally dump the raw stream to X together)\n"
#endif
#ifdef HAVE_LIBLZMA
		" --unxz[=X]            try to filter the tarball stream through xz/lzma/lzip\n"
		"                       (and optionally dump the raw stream to X together)\n"
#endif
#ifdef EROFS_MT_ENABLED
		" --workers=#           set the number of worker threads to # (default=1)\n"
#endif
		" --xattr-prefix=X      X=extra xattr name prefix\n"
		" --mount-point=X       X=prefix of target fs path (default: /)\n"
#ifdef WITH_ANDROID
		"\n"
		"Android-specific options:\n"
		" --product-out=X       X=product_out directory\n"
		" --fs-config-file=X    X=fs_config file\n"
		" --block-list-file=X   X=block_list file\n"
#endif
		);
}

static void version(void)
{
	printf("mkfs.erofs (erofs-utils) %s\navailable compressors: ",
	       cfg.c_version);
	print_available_compressors(stdout, ", ");
}

static unsigned int pclustersize_packed, pclustersize_max;
static struct erofs_tarfile erofstar = {
	.global.xattrs = LIST_HEAD_INIT(erofstar.global.xattrs)
};
static bool tar_mode, rebuild_mode;

static unsigned int rebuild_src_count;
static LIST_HEAD(rebuild_src_list);

static int parse_extended_opts(const char *opts)
{
#define MATCH_EXTENTED_OPT(opt, token, keylen) \
	(keylen == sizeof(opt) - 1 && !memcmp(token, opt, sizeof(opt) - 1))

	const char *token, *next, *tokenend, *value __maybe_unused;
	unsigned int keylen, vallen;

	value = NULL;
	for (token = opts; *token != '\0'; token = next) {
		bool clear = false;
		const char *p = strchr(token, ',');

		next = NULL;
		if (p) {
			next = p + 1;
		} else {
			p = token + strlen(token);
			next = p;
		}

		tokenend = memchr(token, '=', p - token);
		if (tokenend) {
			keylen = tokenend - token;
			vallen = p - tokenend - 1;
			if (!vallen)
				return -EINVAL;

			value = tokenend + 1;
		} else {
			keylen = p - token;
			vallen = 0;
		}

		if (token[0] == '^') {
			if (keylen < 2)
				return -EINVAL;
			++token;
			--keylen;
			clear = true;
		}

		if (MATCH_EXTENTED_OPT("legacy-compress", token, keylen)) {
			if (vallen)
				return -EINVAL;
			/* disable compacted indexes and 0padding */
			cfg.c_legacy_compress = true;
		} else if (MATCH_EXTENTED_OPT("force-inode-compact", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_force_inodeversion = FORCE_INODE_COMPACT;
			cfg.c_ignore_mtime = true;
		} else if (MATCH_EXTENTED_OPT("force-inode-extended", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_force_inodeversion = FORCE_INODE_EXTENDED;
		} else if (MATCH_EXTENTED_OPT("nosbcrc", token, keylen)) {
			if (vallen)
				return -EINVAL;
			erofs_sb_clear_sb_chksum(&sbi);
		} else if (MATCH_EXTENTED_OPT("noinline_data", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_inline_data = false;
		} else if (MATCH_EXTENTED_OPT("inline_data", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_inline_data = !clear;
		} else if (MATCH_EXTENTED_OPT("force-inode-blockmap", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_force_chunkformat = FORCE_INODE_BLOCK_MAP;
		} else if (MATCH_EXTENTED_OPT("force-chunk-indexes", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_force_chunkformat = FORCE_INODE_CHUNK_INDEXES;
		} else if (MATCH_EXTENTED_OPT("ztailpacking", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_ztailpacking = !clear;
		} else if (MATCH_EXTENTED_OPT("all-fragments", token, keylen)) {
			cfg.c_all_fragments = true;
			goto handle_fragment;
		} else if (MATCH_EXTENTED_OPT("fragments", token, keylen)) {
			char *endptr;
			u64 i;

handle_fragment:
			cfg.c_fragments = true;
			if (vallen) {
				i = strtoull(value, &endptr, 0);
				if (endptr - value != vallen) {
					erofs_err("invalid pcluster size for the packed file %s",
						  next);
					return -EINVAL;
				}
				pclustersize_packed = i;
			}
		} else if (MATCH_EXTENTED_OPT("dedupe", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_dedupe = !clear;
		} else if (MATCH_EXTENTED_OPT("xattr-name-filter", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_xattr_name_filter = !clear;
		} else {
			erofs_err("unknown extended option %.*s",
				  p - token, token);
			return -EINVAL;
		}
	}
	return 0;
}

static int mkfs_parse_one_compress_alg(char *alg,
				       struct erofs_compr_opts *copts)
{
	char *p, *q, *opt, *endptr;

	copts->level = -1;
	copts->dict_size = 0;

	p = strchr(alg, ',');
	if (p) {
		copts->alg = strndup(alg, p - alg);

		/* support old '-zlzma,9' form */
		if (isdigit(*(p + 1))) {
			copts->level = strtol(p + 1, &endptr, 10);
			if (*endptr && *endptr != ',') {
				erofs_err("invalid compression level %s",
					  p + 1);
				return -EINVAL;
			}
			return 0;
		}
	} else {
		copts->alg = strdup(alg);
		return 0;
	}

	opt = p + 1;
	while (opt) {
		q = strchr(opt, ',');
		if (q)
			*q = '\0';

		if ((p = strstr(opt, "level="))) {
			p += strlen("level=");
			copts->level = strtol(p, &endptr, 10);
			if ((endptr == p) || (*endptr && *endptr != ',')) {
				erofs_err("invalid compression level %s", p);
				return -EINVAL;
			}
		} else if ((p = strstr(opt, "dictsize="))) {
			p += strlen("dictsize=");
			copts->dict_size = strtoul(p, &endptr, 10);
			if (*endptr == 'k' || *endptr == 'K')
				copts->dict_size <<= 10;
			else if (*endptr == 'm' || *endptr == 'M')
				copts->dict_size <<= 20;
			else if ((endptr == p) || (*endptr && *endptr != ',')) {
				erofs_err("invalid compression dictsize %s", p);
				return -EINVAL;
			}
		} else {
			erofs_err("invalid compression option %s", opt);
			return -EINVAL;
		}

		opt = q ? q + 1 : NULL;
	}

	return 0;
}

static int mkfs_parse_compress_algs(char *algs)
{
	unsigned int i;
	char *s;
	int ret;

	for (s = strtok(algs, ":"), i = 0; s; s = strtok(NULL, ":"), ++i) {
		if (i >= EROFS_MAX_COMPR_CFGS - 1) {
			erofs_err("too many algorithm types");
			return -EINVAL;
		}

		ret = mkfs_parse_one_compress_alg(s, &cfg.c_compr_opts[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static void erofs_rebuild_cleanup(void)
{
	struct erofs_sb_info *src, *n;

	list_for_each_entry_safe(src, n, &rebuild_src_list, list) {
		list_del(&src->list);
		erofs_put_super(src);
		dev_close(src);
		free(src);
	}
	rebuild_src_count = 0;
}

static int mkfs_parse_options_cfg(int argc, char *argv[])
{
	char *endptr;
	int opt, i, err;
	bool quiet = false;
	int tarerofs_decoder = 0;

	while ((opt = getopt_long(argc, argv, "C:E:L:T:U:b:d:x:z:Vh",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'z':
			i = mkfs_parse_compress_algs(optarg);
			if (i)
				return i;
			break;

		case 'b':
			i = atoi(optarg);
			if (i < 512 || i > EROFS_MAX_BLOCK_SIZE) {
				erofs_err("invalid block size %s", optarg);
				return -EINVAL;
			}
			sbi.blkszbits = ilog2(i);
			break;

		case 'd':
			i = atoi(optarg);
			if (i < EROFS_MSG_MIN || i > EROFS_MSG_MAX) {
				erofs_err("invalid debug level %d", i);
				return -EINVAL;
			}
			cfg.c_dbg_lvl = i;
			break;

		case 'x':
			i = strtol(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid xattr tolerance %s", optarg);
				return -EINVAL;
			}
			cfg.c_inline_xattr_tolerance = i;
			break;

		case 'E':
			opt = parse_extended_opts(optarg);
			if (opt)
				return opt;
			break;

		case 'L':
			if (optarg == NULL ||
			    strlen(optarg) > sizeof(sbi.volume_name)) {
				erofs_err("invalid volume label");
				return -EINVAL;
			}
			strncpy(sbi.volume_name, optarg,
				sizeof(sbi.volume_name));
			break;

		case 'T':
			cfg.c_unix_timestamp = strtoull(optarg, &endptr, 0);
			if (cfg.c_unix_timestamp == -1 || *endptr != '\0') {
				erofs_err("invalid UNIX timestamp %s", optarg);
				return -EINVAL;
			}
			cfg.c_timeinherit = TIMESTAMP_FIXED;
			break;
		case 'U':
			if (erofs_uuid_parse(optarg, sbi.uuid)) {
				erofs_err("invalid UUID %s", optarg);
				return -EINVAL;
			}
			break;
		case 2:
			opt = erofs_parse_exclude_path(optarg, false);
			if (opt) {
				erofs_err("failed to parse exclude path: %s",
					  erofs_strerror(opt));
				return opt;
			}
			break;
		case 3:
			opt = erofs_parse_exclude_path(optarg, true);
			if (opt) {
				erofs_err("failed to parse exclude regex: %s",
					  erofs_strerror(opt));
				return opt;
			}
			break;

		case 4:
			opt = erofs_selabel_open(optarg);
			if (opt && opt != -EBUSY)
				return opt;
			break;
		case 5:
			cfg.c_uid = strtoul(optarg, &endptr, 0);
			if (cfg.c_uid == -1 || *endptr != '\0') {
				erofs_err("invalid uid %s", optarg);
				return -EINVAL;
			}
			break;
		case 6:
			cfg.c_gid = strtoul(optarg, &endptr, 0);
			if (cfg.c_gid == -1 || *endptr != '\0') {
				erofs_err("invalid gid %s", optarg);
				return -EINVAL;
			}
			break;
		case 7:
			cfg.c_uid = cfg.c_gid = 0;
			break;
#ifndef NDEBUG
		case 8:
			cfg.c_random_pclusterblks = true;
			break;
		case 18:
			cfg.c_random_algorithms = true;
			break;
#endif
		case 9:
			cfg.c_max_decompressed_extent_bytes =
				strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid maximum uncompressed extent size %s",
					  optarg);
				return -EINVAL;
			}
			break;
		case 10:
			cfg.c_compress_hints_file = optarg;
			break;
		case 512:
			cfg.mount_point = optarg;
			/* all trailing '/' should be deleted */
			opt = strlen(cfg.mount_point);
			if (opt && optarg[opt - 1] == '/')
				optarg[opt - 1] = '\0';
			break;
#ifdef WITH_ANDROID
		case 513:
			cfg.target_out_path = optarg;
			break;
		case 514:
			cfg.fs_config_file = optarg;
			break;
		case 515:
			cfg.block_list_file = optarg;
			break;
#endif
		case 'C':
			i = strtoull(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid physical clustersize %s",
					  optarg);
				return -EINVAL;
			}
			pclustersize_max = i;
			break;
		case 11:
			i = strtol(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid chunksize %s", optarg);
				return -EINVAL;
			}
			cfg.c_chunkbits = ilog2(i);
			if ((1 << cfg.c_chunkbits) != i) {
				erofs_err("chunksize %s must be a power of two",
					  optarg);
				return -EINVAL;
			}
			erofs_sb_set_chunked_file(&sbi);
			break;
		case 12:
			quiet = true;
			break;
		case 13:
			cfg.c_blobdev_path = optarg;
			break;
		case 14:
			cfg.c_ignore_mtime = true;
			break;
		case 15:
			cfg.c_ignore_mtime = false;
			break;
		case 16:
			errno = 0;
			cfg.c_uid_offset = strtoll(optarg, &endptr, 0);
			if (errno || *endptr != '\0') {
				erofs_err("invalid uid offset %s", optarg);
				return -EINVAL;
			}
			break;
		case 17:
			errno = 0;
			cfg.c_gid_offset = strtoll(optarg, &endptr, 0);
			if (errno || *endptr != '\0') {
				erofs_err("invalid gid offset %s", optarg);
				return -EINVAL;
			}
			break;
		case 19:
			errno = 0;
			opt = erofs_xattr_insert_name_prefix(optarg);
			if (opt) {
				erofs_err("failed to parse xattr name prefix: %s",
					  erofs_strerror(opt));
				return opt;
			}
			cfg.c_extra_ea_name_prefixes = true;
			break;
		case 20:
			if (optarg && (!strcmp(optarg, "i") || (!strcmp(optarg, "headerball") ||
				!strcmp(optarg, "0") || !memcmp(optarg, "0,", 2)))) {
				erofstar.index_mode = true;
				if (!memcmp(optarg, "0,", 2))
					erofstar.mapfile = strdup(optarg + 2);
				if (!strcmp(optarg, "headerball"))
					erofstar.headeronly_mode = true;
			}
			tar_mode = true;
			break;
		case 21:
			erofstar.aufs = true;
			break;
		case 516:
			if (!optarg || !strcmp(optarg, "1"))
				cfg.c_ovlfs_strip = true;
			else
				cfg.c_ovlfs_strip = false;
			break;
		case 517:
			sbi.diskoffset = strtoull(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid disk offset %s", optarg);
				return -EINVAL;
			}
			break;
		case 518:
		case 519:
			if (optarg)
				erofstar.dumpfile = strdup(optarg);
			tarerofs_decoder = EROFS_IOS_DECODER_GZIP + (opt - 518);
			break;
#ifdef EROFS_MT_ENABLED
		case 520: {
			unsigned int processors;
			errno = 0;
			cfg.c_mt_workers = strtoul(optarg, &endptr, 0);
			if (errno || *endptr != '\0') {
				erofs_err("invalid worker number %s", optarg);
				return -EINVAL;
			}

			processors = erofs_get_available_processors();
			if (cfg.c_mt_workers > processors)
				erofs_warn("%d workers exceed %d processors, potentially impacting performance.",
					   cfg.c_mt_workers, processors);
			break;
		}
#endif
		case 'V':
			version();
			exit(0);
		case 'h':
			usage(argc, argv);
			exit(0);

		default: /* '?' */
			return -EINVAL;
		}
	}

	if (cfg.c_blobdev_path && cfg.c_chunkbits < sbi.blkszbits) {
		erofs_err("--blobdev must be used together with --chunksize");
		return -EINVAL;
	}

	/* TODO: can be implemented with (deviceslot) mapped_blkaddr */
	if (cfg.c_blobdev_path &&
	    cfg.c_force_chunkformat == FORCE_INODE_BLOCK_MAP) {
		erofs_err("--blobdev cannot work with block map currently");
		return -EINVAL;
	}

	if (optind >= argc) {
		erofs_err("missing argument: FILE");
		return -EINVAL;
	}

	cfg.c_img_path = strdup(argv[optind++]);
	if (!cfg.c_img_path)
		return -ENOMEM;

	if (optind >= argc) {
		if (!tar_mode) {
			erofs_err("missing argument: SOURCE(s)");
			return -EINVAL;
		} else {
			int dupfd;

			dupfd = dup(STDIN_FILENO);
			if (dupfd < 0) {
				erofs_err("failed to duplicate STDIN_FILENO: %s",
					  strerror(errno));
				return -errno;
			}
			err = erofs_iostream_open(&erofstar.ios, dupfd,
						  tarerofs_decoder);
			if (err)
				return err;
		}
	} else {
		struct stat st;

		cfg.c_src_path = realpath(argv[optind++], NULL);
		if (!cfg.c_src_path) {
			erofs_err("failed to parse source directory: %s",
				  erofs_strerror(-errno));
			return -ENOENT;
		}

		if (tar_mode) {
			int fd = open(cfg.c_src_path, O_RDONLY);

			if (fd < 0) {
				erofs_err("failed to open file: %s", cfg.c_src_path);
				return -errno;
			}
			err = erofs_iostream_open(&erofstar.ios, fd,
						  tarerofs_decoder);
			if (err)
				return err;

			if (erofstar.dumpfile) {
				fd = open(erofstar.dumpfile,
					  O_WRONLY | O_CREAT | O_TRUNC, 0644);
				if (fd < 0) {
					erofs_err("failed to open dumpfile: %s",
						  erofstar.dumpfile);
					return -errno;
				}
				erofstar.ios.dumpfd = fd;
			}
		} else {
			err = lstat(cfg.c_src_path, &st);
			if (err)
				return -errno;
			if (S_ISDIR(st.st_mode))
				erofs_set_fs_root(cfg.c_src_path);
			else
				rebuild_mode = true;
		}

		if (rebuild_mode) {
			char *srcpath = cfg.c_src_path;
			struct erofs_sb_info *src;

			do {
				src = calloc(1, sizeof(struct erofs_sb_info));
				if (!src) {
					erofs_rebuild_cleanup();
					return -ENOMEM;
				}

				err = dev_open_ro(src, srcpath);
				if (err) {
					free(src);
					erofs_rebuild_cleanup();
					return err;
				}

				/* extra device index starts from 1 */
				src->dev = ++rebuild_src_count;
				list_add(&src->list, &rebuild_src_list);
			} while (optind < argc && (srcpath = argv[optind++]));
		} else if (optind < argc) {
			erofs_err("unexpected argument: %s\n", argv[optind]);
			return -EINVAL;
		}
	}
	if (quiet) {
		cfg.c_dbg_lvl = EROFS_ERR;
		cfg.c_showprogress = false;
	}

	if (cfg.c_compr_opts[0].alg && erofs_blksiz(&sbi) != getpagesize())
		erofs_warn("Please note that subpage blocksize with compression isn't yet supported in kernel. "
			   "This compressed image will only work with bs = ps = %u bytes",
			   erofs_blksiz(&sbi));

	if (pclustersize_max) {
		if (pclustersize_max < erofs_blksiz(&sbi) ||
		    pclustersize_max % erofs_blksiz(&sbi)) {
			erofs_err("invalid physical clustersize %u",
				  pclustersize_max);
			return -EINVAL;
		}
		cfg.c_mkfs_pclustersize_max = pclustersize_max;
		cfg.c_mkfs_pclustersize_def = cfg.c_mkfs_pclustersize_max;
	}
	if (cfg.c_chunkbits && cfg.c_chunkbits < sbi.blkszbits) {
		erofs_err("chunksize %u must be larger than block size",
			  1u << cfg.c_chunkbits);
		return -EINVAL;
	}

	if (pclustersize_packed) {
		if (pclustersize_packed < erofs_blksiz(&sbi) ||
		    pclustersize_packed % erofs_blksiz(&sbi)) {
			erofs_err("invalid pcluster size for the packed file %u",
				  pclustersize_packed);
			return -EINVAL;
		}
		cfg.c_mkfs_pclustersize_packed = pclustersize_packed;
	}
	return 0;
}

int erofs_mkfs_update_super_block(struct erofs_buffer_head *bh,
				  erofs_nid_t root_nid,
				  erofs_blk_t *blocks,
				  erofs_nid_t packed_nid)
{
	struct erofs_super_block sb = {
		.magic     = cpu_to_le32(EROFS_SUPER_MAGIC_V1),
		.blkszbits = sbi.blkszbits,
		.inos   = cpu_to_le64(sbi.inos),
		.build_time = cpu_to_le64(sbi.build_time),
		.build_time_nsec = cpu_to_le32(sbi.build_time_nsec),
		.blocks = 0,
		.meta_blkaddr  = cpu_to_le32(sbi.meta_blkaddr),
		.xattr_blkaddr = cpu_to_le32(sbi.xattr_blkaddr),
		.xattr_prefix_count = sbi.xattr_prefix_count,
		.xattr_prefix_start = cpu_to_le32(sbi.xattr_prefix_start),
		.feature_incompat = cpu_to_le32(sbi.feature_incompat),
		.feature_compat = cpu_to_le32(sbi.feature_compat &
					      ~EROFS_FEATURE_COMPAT_SB_CHKSUM),
		.extra_devices = cpu_to_le16(sbi.extra_devices),
		.devt_slotoff = cpu_to_le16(sbi.devt_slotoff),
	};
	const u32 sb_blksize = round_up(EROFS_SUPER_END, erofs_blksiz(&sbi));
	char *buf;
	int ret;

	*blocks         = erofs_mapbh(NULL);
	sb.blocks       = cpu_to_le32(*blocks);
	sb.root_nid     = cpu_to_le16(root_nid);
	sb.packed_nid    = cpu_to_le64(packed_nid);
	memcpy(sb.uuid, sbi.uuid, sizeof(sb.uuid));
	memcpy(sb.volume_name, sbi.volume_name, sizeof(sb.volume_name));

	if (erofs_sb_has_compr_cfgs(&sbi))
		sb.u1.available_compr_algs = cpu_to_le16(sbi.available_compr_algs);
	else
		sb.u1.lz4_max_distance = cpu_to_le16(sbi.lz4_max_distance);

	buf = calloc(sb_blksize, 1);
	if (!buf) {
		erofs_err("failed to allocate memory for sb: %s",
			  erofs_strerror(-errno));
		return -ENOMEM;
	}
	memcpy(buf + EROFS_SUPER_OFFSET, &sb, sizeof(sb));

	ret = dev_write(&sbi, buf, erofs_btell(bh, false), EROFS_SUPER_END);
	free(buf);
	erofs_bdrop(bh, false);
	return ret;
}

static int erofs_mkfs_superblock_csum_set(void)
{
	int ret;
	u8 buf[EROFS_MAX_BLOCK_SIZE];
	u32 crc;
	unsigned int len;
	struct erofs_super_block *sb;

	ret = blk_read(&sbi, 0, buf, 0, erofs_blknr(&sbi, EROFS_SUPER_END) + 1);
	if (ret) {
		erofs_err("failed to read superblock to set checksum: %s",
			  erofs_strerror(ret));
		return ret;
	}

	/*
	 * skip the first 1024 bytes, to allow for the installation
	 * of x86 boot sectors and other oddities.
	 */
	sb = (struct erofs_super_block *)(buf + EROFS_SUPER_OFFSET);

	if (le32_to_cpu(sb->magic) != EROFS_SUPER_MAGIC_V1) {
		erofs_err("internal error: not an erofs valid image");
		return -EFAULT;
	}

	/* turn on checksum feature */
	sb->feature_compat = cpu_to_le32(le32_to_cpu(sb->feature_compat) |
					 EROFS_FEATURE_COMPAT_SB_CHKSUM);
	if (erofs_blksiz(&sbi) > EROFS_SUPER_OFFSET)
		len = erofs_blksiz(&sbi) - EROFS_SUPER_OFFSET;
	else
		len = erofs_blksiz(&sbi);
	crc = erofs_crc32c(~0, (u8 *)sb, len);

	/* set up checksum field to erofs_super_block */
	sb->checksum = cpu_to_le32(crc);

	ret = blk_write(&sbi, buf, 0, 1);
	if (ret) {
		erofs_err("failed to write checksummed superblock: %s",
			  erofs_strerror(ret));
		return ret;
	}

	erofs_info("superblock checksum 0x%08x written", crc);
	return 0;
}

static void erofs_mkfs_default_options(void)
{
	cfg.c_showprogress = true;
	cfg.c_legacy_compress = false;
	cfg.c_inline_data = true;
	cfg.c_xattr_name_filter = true;
#ifdef EROFS_MT_ENABLED
	cfg.c_mt_workers = erofs_get_available_processors();
	cfg.c_mkfs_segment_size = 16ULL * 1024 * 1024;
#endif
	sbi.blkszbits = ilog2(min_t(u32, getpagesize(), EROFS_MAX_BLOCK_SIZE));
	cfg.c_mkfs_pclustersize_max = erofs_blksiz(&sbi);
	cfg.c_mkfs_pclustersize_def = cfg.c_mkfs_pclustersize_max;
	sbi.feature_incompat = EROFS_FEATURE_INCOMPAT_ZERO_PADDING;
	sbi.feature_compat = EROFS_FEATURE_COMPAT_SB_CHKSUM |
			     EROFS_FEATURE_COMPAT_MTIME;

	/* generate a default uuid first */
	erofs_uuid_generate(sbi.uuid);
}

/* https://reproducible-builds.org/specs/source-date-epoch/ for more details */
int parse_source_date_epoch(void)
{
	char *source_date_epoch;
	unsigned long long epoch = -1ULL;
	char *endptr;

	source_date_epoch = getenv("SOURCE_DATE_EPOCH");
	if (!source_date_epoch)
		return 0;

	epoch = strtoull(source_date_epoch, &endptr, 10);
	if (epoch == -1ULL || *endptr != '\0') {
		erofs_err("environment variable $SOURCE_DATE_EPOCH %s is invalid",
			  source_date_epoch);
		return -EINVAL;
	}

	if (cfg.c_force_inodeversion != FORCE_INODE_EXTENDED)
		erofs_info("SOURCE_DATE_EPOCH is set, forcely generate extended inodes instead");

	cfg.c_force_inodeversion = FORCE_INODE_EXTENDED;
	cfg.c_unix_timestamp = epoch;
	cfg.c_timeinherit = TIMESTAMP_CLAMPING;
	return 0;
}

void erofs_show_progs(int argc, char *argv[])
{
	if (cfg.c_dbg_lvl >= EROFS_WARN)
		printf("%s %s\n", basename(argv[0]), cfg.c_version);
}
static struct erofs_inode *erofs_alloc_root_inode(void)
{
	struct erofs_inode *root;

	root = erofs_new_inode();
	if (IS_ERR(root))
		return root;
	root->i_srcpath = strdup("/");
	root->i_mode = S_IFDIR | 0777;
	root->i_parent = root;
	root->i_mtime = root->sbi->build_time;
	root->i_mtime_nsec = root->sbi->build_time_nsec;
	erofs_init_empty_dir(root);
	return root;
}

static int erofs_rebuild_load_trees(struct erofs_inode *root)
{
	struct erofs_sb_info *src;
	unsigned int extra_devices = 0;
	erofs_blk_t nblocks;
	int ret, idx;

	list_for_each_entry(src, &rebuild_src_list, list) {
		ret = erofs_rebuild_load_tree(root, src);
		if (ret) {
			erofs_err("failed to load %s", src->devname);
			return ret;
		}
		if (src->extra_devices > 1) {
			erofs_err("%s: unsupported number of extra devices",
				  src->devname, src->extra_devices);
			return -EOPNOTSUPP;
		}
		extra_devices += src->extra_devices;
	}

	if (extra_devices && extra_devices != rebuild_src_count) {
		erofs_err("extra_devices(%u) is mismatched with source images(%u)",
			  extra_devices, rebuild_src_count);
		return -EOPNOTSUPP;
	}

	ret = erofs_mkfs_init_devices(&sbi, rebuild_src_count);
	if (ret)
		return ret;

	list_for_each_entry(src, &rebuild_src_list, list) {
		u8 *tag = NULL;

		if (extra_devices) {
			nblocks = src->devs[0].blocks;
			tag = src->devs[0].tag;
		} else {
			nblocks = src->primarydevice_blocks;
		}
		DBG_BUGON(src->dev < 1);
		idx = src->dev - 1;
		sbi.devs[idx].blocks = nblocks;
		if (tag && *tag)
			memcpy(sbi.devs[idx].tag, tag, sizeof(sbi.devs[0].tag));
		else
			/* convert UUID of the source image to a hex string */
			sprintf((char *)sbi.devs[idx].tag,
				"%04x%04x%04x%04x%04x%04x%04x%04x",
				(src->uuid[0] << 8) | src->uuid[1],
				(src->uuid[2] << 8) | src->uuid[3],
				(src->uuid[4] << 8) | src->uuid[5],
				(src->uuid[6] << 8) | src->uuid[7],
				(src->uuid[8] << 8) | src->uuid[9],
				(src->uuid[10] << 8) | src->uuid[11],
				(src->uuid[12] << 8) | src->uuid[13],
				(src->uuid[14] << 8) | src->uuid[15]);
	}
	return 0;
}

static void erofs_mkfs_showsummaries(erofs_blk_t nblocks)
{
	char uuid_str[37] = {};

	if (!(cfg.c_dbg_lvl > EROFS_ERR && cfg.c_showprogress))
		return;

	erofs_uuid_unparse_lower(sbi.uuid, uuid_str);

	fprintf(stdout, "------\nFilesystem UUID: %s\n"
		"Filesystem total blocks: %u (of %u-byte blocks)\n"
		"Filesystem total inodes: %llu\n"
		"Filesystem total metadata blocks: %u\n"
		"Filesystem total deduplicated bytes (of source files): %llu\n",
		uuid_str, nblocks, 1U << sbi.blkszbits, sbi.inos | 0ULL,
		erofs_total_metablocks(),
		sbi.saved_by_deduplication | 0ULL);
}

int main(int argc, char **argv)
{
	int err = 0;
	struct erofs_buffer_head *sb_bh;
	struct erofs_inode *root_inode, *packed_inode;
	erofs_nid_t root_nid, packed_nid;
	erofs_blk_t nblocks;
	struct timeval t;
	FILE *packedfile = NULL;

	erofs_init_configure();
	erofs_mkfs_default_options();

	err = mkfs_parse_options_cfg(argc, argv);
	erofs_show_progs(argc, argv);
	if (err) {
		if (err == -EINVAL)
			fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		return 1;
	}

	err = parse_source_date_epoch();
	if (err) {
		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		return 1;
	}

	if (cfg.c_unix_timestamp != -1) {
		sbi.build_time      = cfg.c_unix_timestamp;
		sbi.build_time_nsec = 0;
	} else if (!gettimeofday(&t, NULL)) {
		sbi.build_time      = t.tv_sec;
		sbi.build_time_nsec = t.tv_usec;
	}

	err = dev_open(&sbi, cfg.c_img_path);
	if (err) {
		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		return 1;
	}

	if (tar_mode && !erofstar.index_mode) {
		err = erofs_diskbuf_init(1);
		if (err) {
			erofs_err("failed to initialize diskbuf: %s",
				   strerror(-err));
			goto exit;
		}
	}
#ifdef WITH_ANDROID
	if (cfg.fs_config_file &&
	    load_canned_fs_config(cfg.fs_config_file) < 0) {
		erofs_err("failed to load fs config %s", cfg.fs_config_file);
		return 1;
	}

	if (cfg.block_list_file &&
	    erofs_blocklist_open(cfg.block_list_file, false)) {
		erofs_err("failed to open %s", cfg.block_list_file);
		return 1;
	}
#endif
	erofs_show_config();
	if (cfg.c_fragments || cfg.c_extra_ea_name_prefixes) {
		if (!cfg.c_mkfs_pclustersize_packed)
			cfg.c_mkfs_pclustersize_packed = cfg.c_mkfs_pclustersize_def;

		packedfile = erofs_packedfile_init();
		if (IS_ERR(packedfile)) {
			erofs_err("failed to initialize packedfile");
			return 1;
		}
	}

	if (cfg.c_fragments) {
		err = z_erofs_fragments_init();
		if (err) {
			erofs_err("failed to initialize fragments");
			return 1;
		}
	}

#ifndef NDEBUG
	if (cfg.c_random_pclusterblks)
		srand(time(NULL));
#endif
	if (tar_mode && erofstar.index_mode) {
		if (erofstar.mapfile) {
			err = erofs_blocklist_open(erofstar.mapfile, true);
			if (err) {
				erofs_err("failed to open %s", erofstar.mapfile);
				goto exit;
			}
		} else {
			sbi.blkszbits = 9;
		}
	}

	if (rebuild_mode) {
		struct erofs_sb_info *src;

		erofs_warn("EXPERIMENTAL rebuild mode in use. Use at your own risk!");

		src = list_first_entry(&rebuild_src_list, struct erofs_sb_info, list);
		if (!src)
			goto exit;
		err = erofs_read_superblock(src);
		if (err) {
			erofs_err("failed to read superblock of %s", src->devname);
			goto exit;
		}
		sbi.blkszbits = src->blkszbits;
	}

	sb_bh = erofs_buffer_init();
	if (IS_ERR(sb_bh)) {
		err = PTR_ERR(sb_bh);
		erofs_err("failed to initialize buffers: %s",
			  erofs_strerror(err));
		goto exit;
	}
	err = erofs_bh_balloon(sb_bh, EROFS_SUPER_END);
	if (err < 0) {
		erofs_err("failed to balloon erofs_super_block: %s",
			  erofs_strerror(err));
		goto exit;
	}

	/* make sure that the super block should be the very first blocks */
	(void)erofs_mapbh(sb_bh->block);
	if (erofs_btell(sb_bh, false) != 0) {
		erofs_err("failed to reserve erofs_super_block");
		goto exit;
	}

	err = erofs_load_compress_hints(&sbi);
	if (err) {
		erofs_err("failed to load compress hints %s",
			  cfg.c_compress_hints_file);
		goto exit;
	}

	err = z_erofs_compress_init(&sbi, sb_bh);
	if (err) {
		erofs_err("failed to initialize compressor: %s",
			  erofs_strerror(err));
		goto exit;
	}

	if (cfg.c_dedupe) {
		if (!cfg.c_compr_opts[0].alg) {
			erofs_err("Compression is not enabled.  Turn on chunk-based data deduplication instead.");
			cfg.c_chunkbits = sbi.blkszbits;
		} else {
			err = z_erofs_dedupe_init(erofs_blksiz(&sbi));
			if (err) {
				erofs_err("failed to initialize deduplication: %s",
					  erofs_strerror(err));
				goto exit;
			}
		}
	}

	if (cfg.c_chunkbits) {
		err = erofs_blob_init(cfg.c_blobdev_path, 1 << cfg.c_chunkbits);
		if (err)
			return 1;
	}

	if (((erofstar.index_mode && !erofstar.headeronly_mode) &&
	    !erofstar.mapfile) || cfg.c_blobdev_path) {
		err = erofs_mkfs_init_devices(&sbi, 1);
		if (err) {
			erofs_err("failed to generate device table: %s",
				  erofs_strerror(err));
			goto exit;
		}
	}

	erofs_inode_manager_init();

	if (tar_mode) {
		root_inode = erofs_alloc_root_inode();
		if (IS_ERR(root_inode)) {
			err = PTR_ERR(root_inode);
			goto exit;
		}

		while (!(err = tarerofs_parse_tar(root_inode, &erofstar)));

		if (err < 0)
			goto exit;

		err = erofs_rebuild_dump_tree(root_inode);
		if (err < 0)
			goto exit;
	} else if (rebuild_mode) {
		root_inode = erofs_alloc_root_inode();
		if (IS_ERR(root_inode)) {
			err = PTR_ERR(root_inode);
			goto exit;
		}

		err = erofs_rebuild_load_trees(root_inode);
		if (err)
			goto exit;
		err = erofs_rebuild_dump_tree(root_inode);
		if (err)
			goto exit;
	} else {
		err = erofs_build_shared_xattrs_from_path(&sbi, cfg.c_src_path);
		if (err) {
			erofs_err("failed to build shared xattrs: %s",
				  erofs_strerror(err));
			goto exit;
		}

		if (cfg.c_extra_ea_name_prefixes)
			erofs_xattr_write_name_prefixes(&sbi, packedfile);

		root_inode = erofs_mkfs_build_tree_from_path(cfg.c_src_path);
		if (IS_ERR(root_inode)) {
			err = PTR_ERR(root_inode);
			goto exit;
		}
	}
	root_nid = erofs_lookupnid(root_inode);
	erofs_iput(root_inode);

	if (erofstar.index_mode && sbi.extra_devices && !erofstar.mapfile)
		sbi.devs[0].blocks = BLK_ROUND_UP(&sbi, erofstar.offset);

	if (erofstar.index_mode || cfg.c_chunkbits || sbi.extra_devices) {
		err = erofs_mkfs_dump_blobs(&sbi);
		if (err)
			goto exit;
	}

	packed_nid = 0;
	if ((cfg.c_fragments || cfg.c_extra_ea_name_prefixes) &&
	    erofs_sb_has_fragments(&sbi)) {
		erofs_update_progressinfo("Handling packed_file ...");
		packed_inode = erofs_mkfs_build_packedfile();
		if (IS_ERR(packed_inode)) {
			err = PTR_ERR(packed_inode);
			goto exit;
		}
		packed_nid = erofs_lookupnid(packed_inode);
		erofs_iput(packed_inode);
	}

	/* flush all buffers except for the superblock */
	err = erofs_bflush(NULL);
	if (err)
		goto exit;

	err = erofs_mkfs_update_super_block(sb_bh, root_nid, &nblocks,
					    packed_nid);
	if (err)
		goto exit;

	/* flush all remaining buffers */
	err = erofs_bflush(NULL);
	if (err)
		goto exit;

	err = dev_resize(&sbi, nblocks);

	if (!err && erofs_sb_has_sb_chksum(&sbi))
		err = erofs_mkfs_superblock_csum_set();
exit:
	z_erofs_compress_exit();
	z_erofs_dedupe_exit();
	erofs_blocklist_close();
	dev_close(&sbi);
	erofs_cleanup_compress_hints();
	erofs_cleanup_exclude_rules();
	if (cfg.c_chunkbits)
		erofs_blob_exit();
	if (cfg.c_fragments)
		z_erofs_fragments_exit();
	erofs_packedfile_exit();
	erofs_xattr_cleanup_name_prefixes();
	erofs_rebuild_cleanup();
	erofs_diskbuf_exit();
	erofs_exit_configure();
	if (tar_mode) {
		erofs_iostream_close(&erofstar.ios);
		if (erofstar.ios.dumpfd >= 0)
			close(erofstar.ios.dumpfd);
	}

	if (err) {
		erofs_err("\tCould not format the device : %s\n",
			  erofs_strerror(err));
		return 1;
	}
	erofs_update_progressinfo("Build completed.\n");
	erofs_mkfs_showsummaries(nblocks);
	return 0;
}
