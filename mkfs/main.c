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
#include "../lib/liberofs_metabox.h"
#include "../lib/compressor.h"

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
	{"zfeature-bits", required_argument, NULL, 521},
	{"clean", optional_argument, NULL, 522},
	{"incremental", optional_argument, NULL, 523},
	{"root-xattr-isize", required_argument, NULL, 524},
	{"mkfs-time", no_argument, NULL, 525},
	{"all-time", no_argument, NULL, 526},
	{"sort", required_argument, NULL, 527},
	{"hard-dereference", no_argument, NULL, 528},
	{"dsunit", required_argument, NULL, 529},
#ifdef EROFS_MT_ENABLED
	{"async-queue-limit", required_argument, NULL, 530},
#endif
	{"fsalignblks", required_argument, NULL, 531},
	{"vmdk-desc", required_argument, NULL, 532},
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
		" -L volume-label       set the volume label (maximum 15 bytes)\n"
		" -m#[:X]               enable metadata compression (# = physical cluster size in bytes;\n"
		"                                                    X = another compression algorithm for metadata)\n"
		" -T#                   specify a fixed UNIX timestamp # as build time\n"
		"    --all-time         the timestamp is also applied to all files (default)\n"
		"    --mkfs-time        the timestamp is applied as build time only\n"
		" -UX                   use a given filesystem UUID\n"
		" --all-root            make all files owned by root\n"
#ifdef EROFS_MT_ENABLED
		" --async-queue-limit=# specify the maximum number of entries in the multi-threaded job queue\n"
#endif
		" --blobdev=X           specify an extra device X to store chunked data\n"
		" --chunksize=#         generate chunk-based files with #-byte chunks\n"
		" --clean=X             run full clean build (default) or:\n"
		" --incremental=X       run incremental build\n"
		"                       (X = data|rvsp; data=full data, rvsp=space is allocated\n"
		"                                       and filled with zeroes)\n"
		" --compress-hints=X    specify a file to configure per-file compression strategy\n"
		" --dsunit=#            align all data block addresses to multiples of #\n"
		" --exclude-path=X      avoid including file X (X = exact literal path)\n"
		" --exclude-regex=X     avoid including files that match X (X = regular expression)\n"
#ifdef HAVE_LIBSELINUX
		" --file-contexts=X     specify a file contexts file to setup selinux labels\n"
#endif
		" --force-uid=#         set all file uids to # (# = UID)\n"
		" --force-gid=#         set all file gids to # (# = GID)\n"
		" --fsalignblks=#       specify the alignment of the primary device size in blocks\n"
		" --uid-offset=#        add offset # to all file uids (# = id offset)\n"
		" --gid-offset=#        add offset # to all file gids (# = id offset)\n"
		" --hard-dereference    dereference hardlinks, add links as separate inodes\n"
		" --ignore-mtime        use build time instead of strict per-file modification time\n"
		" --max-extent-bytes=#  set maximum decompressed extent size # in bytes\n"
		" --mount-point=X       X=prefix of target fs path (default: /)\n"
		" --preserve-mtime      keep per-file modification time strictly\n"
		" --offset=#            skip # bytes at the beginning of IMAGE.\n"
		" --root-xattr-isize=#  ensure the inline xattr size of the root directory is # bytes at least\n"
		" --aufs                replace aufs special files with overlayfs metadata\n"
		" --sort=<path,none>    data sorting order for tarballs as input (default: path)\n"
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
		" --vmdk-desc=X         generate a VMDK descriptor file to merge sub-filesystems\n"
#ifdef EROFS_MT_ENABLED
		" --workers=#           set the number of worker threads to # (default: %u)\n"
#endif
		" --xattr-prefix=X      X=extra xattr name prefix\n"
		" --zfeature-bits=#     toggle filesystem compression features according to given bits #\n"
#ifdef WITH_ANDROID
		"\n"
		"Android-specific options:\n"
		" --product-out=X       X=product_out directory\n"
		" --fs-config-file=X    X=fs_config file\n"
#endif
#ifdef EROFS_MT_ENABLED
		, erofs_get_available_processors() /* --workers= */
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
static int pclustersize_metabox = -1;
static struct erofs_tarfile erofstar = {
	.global.xattrs = LIST_HEAD_INIT(erofstar.global.xattrs)
};
static bool tar_mode, rebuild_mode, incremental_mode;
static u8 metabox_algorithmid;

enum {
	EROFS_MKFS_DATA_IMPORT_DEFAULT,
	EROFS_MKFS_DATA_IMPORT_FULLDATA,
	EROFS_MKFS_DATA_IMPORT_RVSP,
	EROFS_MKFS_DATA_IMPORT_SPARSE,
} dataimport_mode;

static unsigned int rebuild_src_count, total_ccfgs;
static LIST_HEAD(rebuild_src_list);
static u8 fixeduuid[16];
static bool valid_fixeduuid;
static unsigned int dsunit;
static unsigned int fsalignblks = 1;
static int tarerofs_decoder;
static FILE *vmdk_dcf;

static int erofs_mkfs_feat_set_legacy_compress(bool en, const char *val,
					       unsigned int vallen)
{
	if (vallen)
		return -EINVAL;
	/* disable compacted indexes and 0padding */
	cfg.c_legacy_compress = en;
	return 0;
}

static int erofs_mkfs_feat_set_ztailpacking(bool en, const char *val,
					    unsigned int vallen)
{
	if (vallen)
		return -EINVAL;
	cfg.c_ztailpacking = en;
	return 0;
}

static int erofs_mkfs_feat_set_fragments(bool en, const char *val,
					 unsigned int vallen)
{
	if (!en) {
		if (vallen)
			return -EINVAL;
		cfg.c_fragments = false;
		return 0;
	}

	if (vallen) {
		char *endptr;
		u64 i = strtoull(val, &endptr, 0);

		if (endptr - val != vallen) {
			erofs_err("invalid pcluster size %s for the packed file", val);
			return -EINVAL;
		}
		pclustersize_packed = i;
	}
	cfg.c_fragments = true;
	return 0;
}

static int erofs_mkfs_feat_set_all_fragments(bool en, const char *val,
					     unsigned int vallen)
{
	cfg.c_all_fragments = en;
	return erofs_mkfs_feat_set_fragments(en, val, vallen);
}

static int erofs_mkfs_feat_set_dedupe(bool en, const char *val,
				      unsigned int vallen)
{
	if (vallen)
		return -EINVAL;
	cfg.c_dedupe = en;
	return 0;
}

static int erofs_mkfs_feat_set_fragdedupe(bool en, const char *val,
					  unsigned int vallen)
{
	if (!en) {
		if (vallen)
			return -EINVAL;
		cfg.c_fragdedupe = FRAGDEDUPE_OFF;
	} else if (vallen == sizeof("inode") - 1 &&
		   !memcmp(val, "inode", vallen)) {
		cfg.c_fragdedupe = FRAGDEDUPE_INODE;
	} else {
		cfg.c_fragdedupe = FRAGDEDUPE_FULL;
	}
	return 0;
}

static int erofs_mkfs_feat_set_48bit(bool en, const char *val,
				     unsigned int vallen)
{
	if (vallen)
		return -EINVAL;
	if (en)
		erofs_sb_set_48bit(&g_sbi);
	else
		erofs_sb_clear_48bit(&g_sbi);
	return 0;
}

static int erofs_mkfs_feat_set_dot_omitted(bool en, const char *val,
					   unsigned int vallen)
{
	if (vallen)
		return -EINVAL;

	cfg.c_dot_omitted = en;
	return 0;
}

static struct {
	char *feat;
	int (*set)(bool en, const char *val, unsigned int len);
} z_erofs_mkfs_features[] = {
	{"legacy-compress", erofs_mkfs_feat_set_legacy_compress},
	{"ztailpacking", erofs_mkfs_feat_set_ztailpacking},
	{"fragments", erofs_mkfs_feat_set_fragments},
	{"all-fragments", erofs_mkfs_feat_set_all_fragments},
	{"dedupe", erofs_mkfs_feat_set_dedupe},
	{"fragdedupe", erofs_mkfs_feat_set_fragdedupe},
	{"48bit", erofs_mkfs_feat_set_48bit},
	{"dot-omitted", erofs_mkfs_feat_set_dot_omitted},
	{NULL, NULL},
};

static int parse_extended_opts(const char *opts)
{
#define MATCH_EXTENTED_OPT(opt, token, keylen) \
	(keylen == strlen(opt) && !memcmp(token, opt, keylen))

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

		if (MATCH_EXTENTED_OPT("force-inode-compact", token, keylen)) {
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
			erofs_sb_clear_sb_chksum(&g_sbi);
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
		} else if (MATCH_EXTENTED_OPT("xattr-name-filter", token, keylen)) {
			if (vallen)
				return -EINVAL;
			cfg.c_xattr_name_filter = !clear;
		} else {
			int i, err;

			for (i = 0; z_erofs_mkfs_features[i].feat; ++i) {
				if (!MATCH_EXTENTED_OPT(z_erofs_mkfs_features[i].feat,
							token, keylen))
					continue;
				err = z_erofs_mkfs_features[i].set(!clear, value, vallen);
				if (err)
					return err;
				break;
			}

			if (!z_erofs_mkfs_features[i].feat) {
				erofs_err("unknown extended option %.*s",
					  (int)(p - token), token);
				return -EINVAL;
			}
		}
	}
	return 0;
}

static int mkfs_apply_zfeature_bits(uintmax_t bits)
{
	int i;

	for (i = 0; bits; ++i) {
		int err;

		if (!z_erofs_mkfs_features[i].feat) {
			erofs_err("unsupported zfeature bit %u", i);
			return -EINVAL;
		}
		err = z_erofs_mkfs_features[i].set(bits & 1, NULL, 0);
		if (err) {
			erofs_err("failed to apply zfeature %s",
				  z_erofs_mkfs_features[i].feat);
			return err;
		}
		bits >>= 1;
	}
	return 0;
}

static void mkfs_parse_tar_cfg(char *cfg)
{
	char *p;

	tar_mode = true;
	if (!cfg)
		return;
	p = strchr(cfg, ',');
	if (p) {
		*p = '\0';
		if ((*++p) != '\0')
			erofstar.mapfile = strdup(p);
	}
	if (!strcmp(cfg, "headerball"))
		erofstar.headeronly_mode = true;

	if (erofstar.headeronly_mode || !strcmp(optarg, "i") ||
	    !strcmp(optarg, "0"))
		erofstar.index_mode = true;
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
	char *s;
	int ret;

	for (s = strtok(algs, ":"); s; s = strtok(NULL, ":")) {
		if (total_ccfgs >= EROFS_MAX_COMPR_CFGS - 1) {
			erofs_err("too many algorithm types");
			return -EINVAL;
		}

		ret = mkfs_parse_one_compress_alg(s, &cfg.c_compr_opts[total_ccfgs]);
		if (ret)
			return ret;
		++total_ccfgs;
	}
	return 0;
}

static void erofs_rebuild_cleanup(void)
{
	struct erofs_sb_info *src, *n;

	list_for_each_entry_safe(src, n, &rebuild_src_list, list) {
		list_del(&src->list);
		erofs_put_super(src);
		erofs_dev_close(src);
		free(src);
	}
	rebuild_src_count = 0;
}

static int mkfs_parse_sources(int argc, char *argv[], int optind)
{
	struct stat st;
	int err, fd;
	char *s;

	if (tar_mode) {
		cfg.c_src_path = strdup(argv[optind++]);
		if (!cfg.c_src_path)
			return -ENOMEM;
		fd = open(cfg.c_src_path, O_RDONLY);
		if (fd < 0) {
			erofs_err("failed to open tar file: %s", cfg.c_src_path);
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
		err = lstat((s = argv[optind++]), &st);
		if (err) {
			erofs_err("failed to stat %s: %s", s,
				  erofs_strerror(-errno));
			return -ENOENT;
		}
		if (S_ISDIR(st.st_mode)) {
			cfg.c_src_path = realpath(s, NULL);
			if (!cfg.c_src_path) {
				erofs_err("failed to parse source directory: %s",
					  erofs_strerror(-errno));
				return -ENOENT;
			}
			erofs_set_fs_root(cfg.c_src_path);
		} else {
			cfg.c_src_path = strdup(s);
			if (!cfg.c_src_path)
				return -ENOMEM;
			rebuild_mode = true;
		}
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

			err = erofs_dev_open(src, srcpath, O_RDONLY);
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
	return 0;
}

static int mkfs_parse_options_cfg(int argc, char *argv[])
{
	char *endptr;
	int opt, i, err;
	bool quiet = false;
	bool has_timestamp = false;

	while ((opt = getopt_long(argc, argv, "C:E:L:T:U:b:d:m:x:z:Vh",
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
			g_sbi.blkszbits = ilog2(i);
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
			    strlen(optarg) > (sizeof(g_sbi.volume_name) - 1u)) {
				erofs_err("invalid volume label");
				return -EINVAL;
			}
			strncpy(g_sbi.volume_name, optarg,
				sizeof(g_sbi.volume_name));
			break;

		case 'T':
			cfg.c_unix_timestamp = strtoull(optarg, &endptr, 0);
			if (cfg.c_unix_timestamp == -1 || *endptr != '\0') {
				erofs_err("invalid UNIX timestamp %s", optarg);
				return -EINVAL;
			}
			has_timestamp = true;
			break;
		case 'U':
			if (!strcmp(optarg, "clear")) {
				memset(fixeduuid, 0, 16);
			} else if (!strcmp(optarg, "random")) {
				valid_fixeduuid = false;
				break;
			} else if (erofs_uuid_parse(optarg, fixeduuid)) {
				erofs_err("invalid UUID %s", optarg);
				return -EINVAL;
			}
			valid_fixeduuid = true;
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
		case 'm': {
			char *algid = strchr(optarg, ':');

			if (algid) {
				algid[0] = '\0';
				metabox_algorithmid =
					strtoul(algid + 1, &endptr, 0);
				if (*endptr != '\0') {
					err = mkfs_parse_one_compress_alg(algid + 1,
							&cfg.c_compr_opts[total_ccfgs]);
					if (err)
						return err;
					metabox_algorithmid = total_ccfgs++;
				}
			}
			pclustersize_metabox = atoi(optarg);
			break;
		}

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
			erofs_sb_set_chunked_file(&g_sbi);
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
			mkfs_parse_tar_cfg(optarg);
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
			g_sbi.bdev.offset = strtoull(optarg, &endptr, 0);
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
		case 521:
			errno = 0;
			i = strtol(optarg, &endptr, 0);
			if (errno || *endptr != '\0') {
				erofs_err("invalid zfeature bits %s", optarg);
				return -EINVAL;
			}
			err = mkfs_apply_zfeature_bits(i);
			if (err)
				return err;
			break;
		case 522:
		case 523:
			if (!optarg || !strcmp(optarg, "data")) {
				dataimport_mode = EROFS_MKFS_DATA_IMPORT_FULLDATA;
			} else if (!strcmp(optarg, "rvsp")) {
				dataimport_mode = EROFS_MKFS_DATA_IMPORT_RVSP;
			} else {
				errno = 0;
				dataimport_mode = strtol(optarg, &endptr, 0);
				if (errno || *endptr != '\0') {
					erofs_err("invalid --%s=%s",
						  opt == 523 ? "incremental" : "clean", optarg);
					return -EINVAL;
				}
			}
			incremental_mode = (opt == 523);
			break;
		case 524:
			cfg.c_root_xattr_isize = strtoull(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid the minimum inline xattr size %s", optarg);
				return -EINVAL;
			}
			break;
		case 525:
			cfg.c_timeinherit = TIMESTAMP_NONE;
			break;
		case 526:
			cfg.c_timeinherit = TIMESTAMP_FIXED;
			break;
		case 527:
			if (!strcmp(optarg, "none"))
				erofstar.try_no_reorder = true;
			break;
		case 528:
			cfg.c_hard_dereference = true;
			break;
		case 529:
			dsunit = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid dsunit %s", optarg);
				return -EINVAL;
			}
			break;
#ifdef EROFS_MT_ENABLED
		case 530:
			cfg.c_mt_async_queue_limit = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid async-queue-limit %s", optarg);
				return -EINVAL;
			}
			break;
#endif
		case 531:
			fsalignblks = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid fsalignblks %s", optarg);
				return -EINVAL;
			}
			break;
		case 532:
			vmdk_dcf = fopen(optarg, "wb");
			if (!vmdk_dcf) {
				erofs_err("failed to open vmdk desc `%s`", optarg);
				return -EINVAL;
			}
			break;
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

	if (cfg.c_blobdev_path && cfg.c_chunkbits < g_sbi.blkszbits) {
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

	if (optind < argc) {
		err = mkfs_parse_sources(argc, argv, optind);
		if (err)
			return err;
	} else if (!tar_mode) {
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

	if (quiet) {
		cfg.c_dbg_lvl = EROFS_ERR;
		cfg.c_showprogress = false;
	}

	if (pclustersize_max) {
		if (pclustersize_max < erofs_blksiz(&g_sbi) ||
		    pclustersize_max % erofs_blksiz(&g_sbi)) {
			erofs_err("invalid physical clustersize %u",
				  pclustersize_max);
			return -EINVAL;
		}
		cfg.c_mkfs_pclustersize_max = pclustersize_max;
		cfg.c_mkfs_pclustersize_def = cfg.c_mkfs_pclustersize_max;
	}
	if (cfg.c_chunkbits && cfg.c_chunkbits < g_sbi.blkszbits) {
		erofs_err("chunksize %u must be larger than block size",
			  1u << cfg.c_chunkbits);
		return -EINVAL;
	}

	if (pclustersize_packed) {
		if (pclustersize_packed < erofs_blksiz(&g_sbi) ||
		    pclustersize_packed % erofs_blksiz(&g_sbi)) {
			erofs_err("invalid pcluster size for the packed file %u",
				  pclustersize_packed);
			return -EINVAL;
		}
		cfg.c_mkfs_pclustersize_packed = pclustersize_packed;
	}

	if (pclustersize_metabox >= 0) {
		if (pclustersize_metabox &&
		    (pclustersize_metabox < erofs_blksiz(&g_sbi) ||
		     pclustersize_metabox % erofs_blksiz(&g_sbi))) {
			erofs_err("invalid pcluster size %u for the metabox inode",
				  pclustersize_metabox);
			return -EINVAL;
		}
		cfg.c_mkfs_pclustersize_metabox = pclustersize_metabox;
		cfg.c_mkfs_metabox_algid = metabox_algorithmid;
	}

	if (has_timestamp && cfg.c_timeinherit == TIMESTAMP_UNSPECIFIED)
		cfg.c_timeinherit = TIMESTAMP_FIXED;
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
	g_sbi.blkszbits = ilog2(min_t(u32, getpagesize(), EROFS_MAX_BLOCK_SIZE));
	cfg.c_mkfs_pclustersize_max = erofs_blksiz(&g_sbi);
	cfg.c_mkfs_pclustersize_def = cfg.c_mkfs_pclustersize_max;
	g_sbi.feature_incompat = EROFS_FEATURE_INCOMPAT_ZERO_PADDING;
	g_sbi.feature_compat = EROFS_FEATURE_COMPAT_SB_CHKSUM |
			     EROFS_FEATURE_COMPAT_MTIME;
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
	cfg.c_unix_timestamp = epoch;
	cfg.c_timeinherit = TIMESTAMP_CLAMPING;
	return 0;
}

void erofs_show_progs(int argc, char *argv[])
{
	if (cfg.c_dbg_lvl >= EROFS_WARN)
		printf("%s %s\n", basename(argv[0]), cfg.c_version);
}

static int erofs_mkfs_rebuild_load_trees(struct erofs_inode *root)
{
	struct erofs_device_info *devs;
	struct erofs_sb_info *src;
	unsigned int extra_devices = 0;
	erofs_blk_t nblocks;
	int ret, idx;
	enum erofs_rebuild_datamode datamode;

	switch (dataimport_mode) {
	case EROFS_MKFS_DATA_IMPORT_DEFAULT:
		datamode = EROFS_REBUILD_DATA_BLOB_INDEX;
		break;
	case EROFS_MKFS_DATA_IMPORT_FULLDATA:
		datamode = EROFS_REBUILD_DATA_FULL;
		break;
	case EROFS_MKFS_DATA_IMPORT_RVSP:
		datamode = EROFS_REBUILD_DATA_RESVSP;
		break;
	default:
		return -EINVAL;
	}

	list_for_each_entry(src, &rebuild_src_list, list) {
		ret = erofs_rebuild_load_tree(root, src, datamode);
		if (ret) {
			erofs_err("failed to load %s", src->devname);
			return ret;
		}
		if (src->extra_devices > 1) {
			erofs_err("%s: unsupported number %u of extra devices",
				  src->devname, src->extra_devices);
			return -EOPNOTSUPP;
		}
		extra_devices += src->extra_devices;
	}

	if (datamode != EROFS_REBUILD_DATA_BLOB_INDEX)
		return 0;

	/* Each blob has either no extra device or only one device for TarFS */
	if (extra_devices && extra_devices != rebuild_src_count) {
		erofs_err("extra_devices(%u) is mismatched with source images(%u)",
			  extra_devices, rebuild_src_count);
		return -EOPNOTSUPP;
	}

	ret = erofs_mkfs_init_devices(&g_sbi, rebuild_src_count);
	if (ret)
		return ret;

	devs = g_sbi.devs;
	list_for_each_entry(src, &rebuild_src_list, list) {
		u8 *tag = NULL;

		DBG_BUGON(src->dev < 1);
		idx = src->dev - 1;
		if (extra_devices) {
			nblocks = src->devs[0].blocks;
			tag = src->devs[0].tag;
		} else {
			nblocks = src->primarydevice_blocks;
			devs[idx].src_path = strdup(src->devname);
		}
		devs[idx].blocks = nblocks;
		if (tag && *tag)
			memcpy(devs[idx].tag, tag, sizeof(devs[0].tag));
		else
			/* convert UUID of the source image to a hex string */
			sprintf((char *)g_sbi.devs[idx].tag,
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

static void erofs_mkfs_showsummaries(void)
{
	char uuid_str[37] = {};
	char *incr = incremental_mode ? "new" : "total";

	if (!(cfg.c_dbg_lvl > EROFS_ERR && cfg.c_showprogress))
		return;

	erofs_uuid_unparse_lower(g_sbi.uuid, uuid_str);

	fprintf(stdout, "------\nFilesystem UUID: %s\n"
		"Filesystem total blocks: %llu (of %u-byte blocks)\n"
		"Filesystem total inodes: %llu\n"
		"Filesystem %s metadata blocks: %llu\n"
		"Filesystem %s deduplicated bytes (of source files): %llu\n",
		uuid_str, g_sbi.total_blocks | 0ULL, 1U << g_sbi.blkszbits,
		g_sbi.inos | 0ULL,
		incr, erofs_total_metablocks(g_sbi.bmgr) | 0ULL,
		incr, g_sbi.saved_by_deduplication | 0ULL);
}

int main(int argc, char **argv)
{
	struct erofs_buffer_head *sb_bh;
	struct erofs_inode *root = NULL;
	bool tar_index_512b = false;
	struct timeval t;
	FILE *blklst = NULL;
	s64 mkfs_time = 0;
	int err = 0;
	u32 crc;

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

	g_sbi.fixed_nsec = 0;
	if (cfg.c_unix_timestamp != -1) {
		mkfs_time = cfg.c_unix_timestamp;
	} else if (!gettimeofday(&t, NULL)) {
		mkfs_time = t.tv_sec;
	}
	if (erofs_sb_has_48bit(&g_sbi)) {
		g_sbi.epoch = max_t(s64, 0, mkfs_time - UINT32_MAX);
		g_sbi.build_time = mkfs_time - g_sbi.epoch;
	} else {
		g_sbi.epoch = mkfs_time;
	}

	if (cfg.c_dot_omitted)
		erofs_sb_set_48bit(&g_sbi);

	err = erofs_dev_open(&g_sbi, cfg.c_img_path, O_RDWR |
				(incremental_mode ? 0 : O_TRUNC));
	if (err) {
		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		return 1;
	}

#ifdef WITH_ANDROID
	if (cfg.fs_config_file &&
	    load_canned_fs_config(cfg.fs_config_file) < 0) {
		erofs_err("failed to load fs config %s", cfg.fs_config_file);
		return 1;
	}
#endif
	erofs_show_config();
	if (cfg.c_fragments || cfg.c_extra_ea_name_prefixes) {
		if (!cfg.c_mkfs_pclustersize_packed)
			cfg.c_mkfs_pclustersize_packed = cfg.c_mkfs_pclustersize_def;

		err = erofs_packedfile_init(&g_sbi, cfg.c_fragments);
		if (err) {
			erofs_err("failed to initialize packedfile: %s",
				  strerror(-err));
			return 1;
		}
	}

	if (cfg.c_mkfs_pclustersize_metabox >= 0) {
		err = erofs_metabox_init(&g_sbi);
		if (err) {
			erofs_err("failed to initialize metabox: %s",
				  erofs_strerror(err));
			return 1;
		}
	}

#ifndef NDEBUG
	if (cfg.c_random_pclusterblks)
		srand(time(NULL));
#endif
	if (tar_mode) {
		if (dataimport_mode == EROFS_MKFS_DATA_IMPORT_RVSP)
			erofstar.rvsp_mode = true;
		erofstar.dev = rebuild_src_count + 1;

		if (erofstar.mapfile) {
			blklst = fopen(erofstar.mapfile, "w");
			if (!blklst || erofs_blocklist_open(blklst, true)) {
				err = -errno;
				erofs_err("failed to open %s", erofstar.mapfile);
				goto exit;
			}
		} else if (erofstar.index_mode && !erofstar.headeronly_mode) {
			/*
			 * If mapfile is unspecified for tarfs index mode,
			 * 512-byte block size is enforced here.
			 */
			g_sbi.blkszbits = 9;
			tar_index_512b = true;
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
		g_sbi.blkszbits = src->blkszbits;
	}

	if (!incremental_mode) {
		g_sbi.bmgr = erofs_buffer_init(&g_sbi, 0, NULL);
		if (!g_sbi.bmgr) {
			err = -ENOMEM;
			goto exit;
		}
		sb_bh = erofs_reserve_sb(g_sbi.bmgr);
		if (IS_ERR(sb_bh)) {
			err = PTR_ERR(sb_bh);
			goto exit;
		}
	} else {
		union {
			struct stat st;
			erofs_blk_t startblk;
		} u;

		erofs_warn("EXPERIMENTAL incremental build in use. Use at your own risk!");
		err = erofs_read_superblock(&g_sbi);
		if (err) {
			erofs_err("failed to read superblock of %s", g_sbi.devname);
			goto exit;
		}

		err = erofs_io_fstat(&g_sbi.bdev, &u.st);
		if (!err && S_ISREG(u.st.st_mode))
			u.startblk = DIV_ROUND_UP(u.st.st_size, erofs_blksiz(&g_sbi));
		else
			u.startblk = g_sbi.primarydevice_blocks;
		g_sbi.bmgr = erofs_buffer_init(&g_sbi, u.startblk, NULL);
		if (!g_sbi.bmgr) {
			err = -ENOMEM;
			goto exit;
		}
		sb_bh = NULL;
	}
	g_sbi.bmgr->dsunit = dsunit;

	/* Use the user-defined UUID or generate one for clean builds */
	if (valid_fixeduuid)
		memcpy(g_sbi.uuid, fixeduuid, sizeof(g_sbi.uuid));
	else if (!incremental_mode)
		erofs_uuid_generate(g_sbi.uuid);

	if (tar_mode && !erofstar.index_mode) {
		err = erofs_diskbuf_init(1);
		if (err) {
			erofs_err("failed to initialize diskbuf: %s",
				   strerror(-err));
			goto exit;
		}
	}

	err = erofs_load_compress_hints(&g_sbi);
	if (err) {
		erofs_err("failed to load compress hints %s",
			  cfg.c_compress_hints_file);
		goto exit;
	}

	err = z_erofs_compress_init(&g_sbi, sb_bh);
	if (err) {
		erofs_err("failed to initialize compressor: %s",
			  erofs_strerror(err));
		goto exit;
	}

	if (cfg.c_dedupe) {
		if (!cfg.c_compr_opts[0].alg) {
			erofs_err("Compression is not enabled.  Turn on chunk-based data deduplication instead.");
			cfg.c_chunkbits = g_sbi.blkszbits;
		} else {
			err = z_erofs_dedupe_init(erofs_blksiz(&g_sbi));
			if (err) {
				erofs_err("failed to initialize deduplication: %s",
					  erofs_strerror(err));
				goto exit;
			}
		}
	}

	if (cfg.c_fragments) {
		err = z_erofs_dedupe_ext_init();
		if (err) {
			erofs_err("failed to initialize extent deduplication: %s",
				  erofs_strerror(err));
			goto exit;
		}
	}

	if (cfg.c_chunkbits) {
		err = erofs_blob_init(cfg.c_blobdev_path, 1 << cfg.c_chunkbits);
		if (err)
			return 1;
	}

	if (tar_index_512b || cfg.c_blobdev_path) {
		err = erofs_mkfs_init_devices(&g_sbi, 1);
		if (err) {
			erofs_err("failed to generate device table: %s",
				  erofs_strerror(err));
			goto exit;
		}
	}

	erofs_inode_manager_init();

	if (tar_mode) {
		root = erofs_rebuild_make_root(&g_sbi);
		if (IS_ERR(root)) {
			err = PTR_ERR(root);
			goto exit;
		}

		while (!(err = tarerofs_parse_tar(root, &erofstar)));

		if (err < 0)
			goto exit;

		err = erofs_rebuild_dump_tree(root, incremental_mode);
		if (err < 0)
			goto exit;
	} else if (rebuild_mode) {
		root = erofs_rebuild_make_root(&g_sbi);
		if (IS_ERR(root)) {
			err = PTR_ERR(root);
			goto exit;
		}

		err = erofs_mkfs_rebuild_load_trees(root);
		if (err)
			goto exit;
		err = erofs_rebuild_dump_tree(root, incremental_mode);
		if (err)
			goto exit;
	} else {
		err = erofs_build_shared_xattrs_from_path(&g_sbi, cfg.c_src_path);
		if (err) {
			erofs_err("failed to build shared xattrs: %s",
				  erofs_strerror(err));
			goto exit;
		}

		if (cfg.c_extra_ea_name_prefixes)
			erofs_xattr_flush_name_prefixes(&g_sbi);

		root = erofs_mkfs_build_tree_from_path(&g_sbi, cfg.c_src_path);
		if (IS_ERR(root)) {
			err = PTR_ERR(root);
			root = NULL;
			goto exit;
		}
	}

	if (tar_index_512b) {
		if (!g_sbi.extra_devices) {
			DBG_BUGON(1);
		} else {
			if (cfg.c_src_path)
				g_sbi.devs[0].src_path = strdup(cfg.c_src_path);
			g_sbi.devs[0].blocks =
				BLK_ROUND_UP(&g_sbi, erofstar.offset);
		}
	}

	if (erofs_sb_has_metabox(&g_sbi)) {
		erofs_update_progressinfo("Handling metabox ...");
		erofs_metabox_iflush(&g_sbi);
		if (err)
			goto exit;
	}

	if ((cfg.c_fragments || cfg.c_extra_ea_name_prefixes) &&
	    erofs_sb_has_fragments(&g_sbi)) {
		erofs_update_progressinfo("Handling packed data ...");
		err = erofs_flush_packed_inode(&g_sbi);
		if (err)
			goto exit;
	}

	if (erofstar.index_mode || cfg.c_chunkbits || g_sbi.extra_devices) {
		err = erofs_mkfs_dump_blobs(&g_sbi);
		if (err)
			goto exit;
	}

	g_sbi.primarydevice_blocks =
		roundup(erofs_mapbh(g_sbi.bmgr, NULL), fsalignblks);
	err = erofs_write_device_table(&g_sbi);
	if (err)
		goto exit;

	/* flush all buffers except for the superblock */
	err = erofs_bflush(g_sbi.bmgr, NULL);
	if (err)
		goto exit;

	erofs_fixup_root_inode(root);
	erofs_iput(root);
	root = NULL;

	err = erofs_writesb(&g_sbi, sb_bh);
	if (err)
		goto exit;

	/* flush all remaining buffers */
	err = erofs_bflush(g_sbi.bmgr, NULL);
	if (err)
		goto exit;

	err = erofs_dev_resize(&g_sbi, g_sbi.primarydevice_blocks);

	if (!err && erofs_sb_has_sb_chksum(&g_sbi)) {
		err = erofs_enable_sb_chksum(&g_sbi, &crc);
		if (!err)
			erofs_info("superblock checksum 0x%08x written", crc);
	}

	if (!err && vmdk_dcf) {
		err = erofs_dump_vmdk_desc(vmdk_dcf, &g_sbi);
		fclose(vmdk_dcf);
	}
exit:
	if (root)
		erofs_iput(root);
	erofs_metabox_exit(&g_sbi);
	z_erofs_compress_exit(&g_sbi);
	z_erofs_dedupe_exit();
	z_erofs_dedupe_ext_exit();
	blklst = erofs_blocklist_close();
	if (blklst)
		fclose(blklst);
	erofs_dev_close(&g_sbi);
	erofs_cleanup_compress_hints();
	erofs_cleanup_exclude_rules();
	if (cfg.c_chunkbits)
		erofs_blob_exit();
	erofs_packedfile_exit(&g_sbi);
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
	erofs_mkfs_showsummaries();
	erofs_put_super(&g_sbi);
	return 0;
}
