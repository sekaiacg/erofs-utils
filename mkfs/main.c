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
#include "erofs/importer.h"
#include "erofs/diskbuf.h"
#include "erofs/inode.h"
#include "erofs/tar.h"
#include "erofs/dedupe.h"
#include "erofs/xattr.h"
#include "erofs/exclude.h"
#include "erofs/block_list.h"
#include "erofs/compress_hints.h"
#include "erofs/blobchunk.h"
#include "../lib/compressor.h"
#include "../lib/liberofs_gzran.h"
#include "../lib/liberofs_metabox.h"
#include "../lib/liberofs_oci.h"
#include "../lib/liberofs_private.h"
#include "../lib/liberofs_rebuild.h"
#include "../lib/liberofs_s3.h"
#include "../lib/liberofs_uuid.h"

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
	{"gzinfo", optional_argument, NULL, 535},
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
#ifdef EROFS_MT_ENABLED
	{"async-queue-limit", required_argument, NULL, 530},
#endif
	{"fsalignblks", required_argument, NULL, 531},
	{"vmdk-desc", required_argument, NULL, 532},
#ifdef S3EROFS_ENABLED
	{"s3", required_argument, NULL, 533},
#endif
#ifdef OCIEROFS_ENABLED
	{"oci", optional_argument, NULL, 534},
#endif
	{"zD", optional_argument, NULL, 536},
	{"ZI", optional_argument, NULL, 537},
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
		" --zD[=<0|1>]          specify directory compression: 0=disable [default], 1=enable\n"
		" --ZI[=<0|1>]          specify the separate inode metadata zone availability: 0=disable [default], 1=enable\n"
		" --all-root            make all files owned by root\n"
#ifdef EROFS_MT_ENABLED
		" --async-queue-limit=# specify the maximum number of entries in the multi-threaded job queue\n"
#endif
		" --blobdev=X           specify an extra device X to store chunked data\n"
		" --chunksize=#         generate chunk-based files with #-byte chunks\n"
		" --clean=X             run full clean build (default) or:\n"
		" --incremental=X       run incremental build\n"
		"                       X = data|rvsp|0 (data: full data, rvsp: space fallocated\n"
		"                                        0: inodes zeroed)\n"
		" --compress-hints=X    specify a file to configure per-file compression strategy\n"
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
#ifdef S3EROFS_ENABLED
		" --s3=X                generate an image from S3-compatible object store\n"
		"   [,passwd_file=Y]    X=endpoint, Y=s3fs-compatible password file\n"
		"   [,urlstyle=Z]       S3 API calling style (Z = vhost|path) (default: vhost)\n"
		"   [,sig=<2,4>]        S3 API signature version (default: 2)\n"
		"   [,region=W]         W=region code in which endpoint belongs to (required for sig=4)\n"
#endif
#ifdef OCIEROFS_ENABLED
		" --oci=[f|i]           generate a full (f) or index-only (i) image from OCI remote source\n"
		"   [,=platform=X]      X=platform (default: linux/amd64)\n"
		"   [,layer=#]          #=layer index to extract (0-based; omit to extract all layers)\n"
		"   [,blob=Y]           Y=blob digest to extract (omit to extract all layers)\n"
		"   [,username=Z]       Z=username for authentication (optional)\n"
		"   [,password=W]       W=password for authentication (optional)\n"
#endif
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
#ifdef HAVE_ZLIB
		" --gzinfo[=X]          generate AWS SOCI-compatible zinfo in order to support random gzip access\n"
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

static struct erofsmkfs_cfg {
	/* < 0, xattr disabled and >= INT_MAX, always use inline xattrs */
	long inlinexattr_tolerance;
	bool inode_metazone;
} mkfscfg = {
	.inlinexattr_tolerance = 2,
};

static unsigned int pclustersize_packed, pclustersize_max;
static int pclustersize_metabox = -1;
static struct erofs_tarfile erofstar = {
	.global.xattrs = LIST_HEAD_INIT(erofstar.global.xattrs)
};
static bool incremental_mode;
static u8 metabox_algorithmid;

#ifdef S3EROFS_ENABLED
static struct erofs_s3 s3cfg;
#endif

#ifdef OCIEROFS_ENABLED
static struct ocierofs_config ocicfg;
#endif
static bool mkfs_oci_tarindex_mode;

enum {
	EROFS_MKFS_DATA_IMPORT_DEFAULT,
	EROFS_MKFS_DATA_IMPORT_FULLDATA,
	EROFS_MKFS_DATA_IMPORT_RVSP,
	EROFS_MKFS_DATA_IMPORT_ZEROFILL,
} dataimport_mode;

static enum {
	EROFS_MKFS_SOURCE_LOCALDIR,
	EROFS_MKFS_SOURCE_TAR,
	EROFS_MKFS_SOURCE_S3,
	EROFS_MKFS_SOURCE_OCI,
	EROFS_MKFS_SOURCE_REBUILD,
} source_mode;

static unsigned int rebuild_src_count, total_ccfgs;
static LIST_HEAD(rebuild_src_list);
static u8 fixeduuid[16];
static bool valid_fixeduuid;
static int tarerofs_decoder;
static FILE *vmdk_dcf;
static char *mkfs_aws_zinfo_file;

static int erofs_mkfs_feat_set_legacy_compress(struct erofs_importer_params *params,
					       bool en, const char *val,
					       unsigned int vallen)
{
	if (vallen)
		return -EINVAL;
	/* disable compacted indexes and 0padding */
	params->no_zcompact = true;
	params->no_lz4_0padding = true;
	return 0;
}

static int erofs_mkfs_feat_set_ztailpacking(struct erofs_importer_params *params,
					    bool en, const char *val,
					    unsigned int vallen)
{
	if (vallen)
		return -EINVAL;

	params->ztailpacking = en;
	return 0;
}

static int erofs_mkfs_feat_set_fragments(struct erofs_importer_params *params,
					 bool en, const char *val,
					 unsigned int vallen)
{
	if (!en) {
		if (vallen)
			return -EINVAL;
		params->fragments = false;
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
	params->fragments = true;
	return 0;
}

static int erofs_mkfs_feat_set_all_fragments(struct erofs_importer_params *params,
					     bool en, const char *val,
					     unsigned int vallen)
{
	params->all_fragments = en;
	return erofs_mkfs_feat_set_fragments(params, en, val, vallen);
}

static int erofs_mkfs_feat_set_dedupe(struct erofs_importer_params *params,
				      bool en, const char *val,
				      unsigned int vallen)
{
	if (vallen)
		return -EINVAL;
	params->dedupe = en ? EROFS_DEDUPE_FORCE_ON : EROFS_DEDUPE_FORCE_OFF;
	return 0;
}

static int erofs_mkfs_feat_set_fragdedupe(struct erofs_importer_params *params,
					  bool en, const char *val,
					  unsigned int vallen)
{
	if (!en) {
		if (vallen)
			return -EINVAL;
		params->fragdedupe = EROFS_FRAGDEDUPE_OFF;
	} else if (vallen == sizeof("inode") - 1 &&
		   !memcmp(val, "inode", vallen)) {
		params->fragdedupe = EROFS_FRAGDEDUPE_INODE;
	} else {
		params->fragdedupe = EROFS_FRAGDEDUPE_FULL;
	}
	return 0;
}

static int erofs_mkfs_feat_set_48bit(struct erofs_importer_params *params,
				     bool en, const char *val,
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

static bool mkfs_dot_omitted;
static unsigned char mkfs_blkszbits;

static int erofs_mkfs_feat_set_dot_omitted(struct erofs_importer_params *params,
					   bool en, const char *val,
					   unsigned int vallen)
{
	if (vallen)
		return -EINVAL;

	mkfs_dot_omitted = en;
	return 0;
}

static struct {
	char *feat;
	int (*set)(struct erofs_importer_params *params, bool en,
		   const char *val, unsigned int len);
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

static bool mkfs_no_datainline;
static bool mkfs_plain_xattr_pfx;

static int parse_extended_opts(struct erofs_importer_params *params,
			       const char *opts)
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
			params->force_inodeversion = EROFS_FORCE_INODE_COMPACT;
			params->ignore_mtime = true;
		} else if (MATCH_EXTENTED_OPT("force-inode-extended", token, keylen)) {
			if (vallen)
				return -EINVAL;
			params->force_inodeversion = EROFS_FORCE_INODE_EXTENDED;
		} else if (MATCH_EXTENTED_OPT("nosbcrc", token, keylen)) {
			if (vallen)
				return -EINVAL;
			erofs_sb_clear_sb_chksum(&g_sbi);
		} else if (MATCH_EXTENTED_OPT("noinline_data", token, keylen)) {
			if (vallen)
				return -EINVAL;
			mkfs_no_datainline = true;
		} else if (MATCH_EXTENTED_OPT("inline_data", token, keylen)) {
			if (vallen)
				return -EINVAL;
			mkfs_no_datainline = !!clear;
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
		} else if (MATCH_EXTENTED_OPT("plain-xattr-prefixes", token, keylen)) {
			if (vallen)
				return -EINVAL;
			mkfs_plain_xattr_pfx = true;
		} else {
			int i, err;

			for (i = 0; z_erofs_mkfs_features[i].feat; ++i) {
				if (!MATCH_EXTENTED_OPT(z_erofs_mkfs_features[i].feat,
							token, keylen))
					continue;
				err = z_erofs_mkfs_features[i].set(params,
						!clear, value, vallen);
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

static int mkfs_apply_zfeature_bits(struct erofs_importer_params *params,
				    uintmax_t bits)
{
	int i;

	for (i = 0; bits; ++i) {
		int err;

		if (!z_erofs_mkfs_features[i].feat) {
			erofs_err("unsupported zfeature bit %u", i);
			return -EINVAL;
		}
		err = z_erofs_mkfs_features[i].set(params, bits & 1, NULL, 0);
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

	source_mode = EROFS_MKFS_SOURCE_TAR;
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

#ifdef S3EROFS_ENABLED
static int mkfs_parse_s3_cfg_passwd(const char *filepath, char *ak, char *sk)
{
	struct stat st;
	int fd, n, ret;
	char buf[S3_ACCESS_KEY_LEN + S3_SECRET_KEY_LEN + 3];
	char *colon;

	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		erofs_err("failed to open passwd_file %s", filepath);
		return -errno;
	}

	ret = fstat(fd, &st);
	if (ret) {
		ret = -errno;
		goto err;
	}

	if (!S_ISREG(st.st_mode)) {
		erofs_err("%s is not a regular file", filepath);
		ret = -EINVAL;
		goto err;
	}

	if ((st.st_mode & 077) != 0)
		erofs_warn("passwd_file %s should not be accessible by group or others",
			   filepath);

	if (st.st_size > S3_ACCESS_KEY_LEN + S3_SECRET_KEY_LEN + 3) {
		erofs_err("passwd_file %s is too large (size: %llu)", filepath,
			  st.st_size | 0ULL);
		ret = -EINVAL;
		goto err;
	}

	n = read(fd, buf, st.st_size);
	if (n < 0) {
		ret = -errno;
		goto err;
	}
	buf[n] = '\0';

	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';

	colon = strchr(buf, ':');
	if (!colon) {
		ret = -EINVAL;
		goto err;
	}
	*colon = '\0';

	strcpy(ak, buf);
	strcpy(sk, colon + 1);

err:
	close(fd);
	return ret;
}

static int mkfs_parse_s3_cfg(char *cfg_str)
{
	char *p, *q, *opt;
	int ret = 0;

	if (source_mode != EROFS_MKFS_SOURCE_LOCALDIR)
		return -EINVAL;
	source_mode = EROFS_MKFS_SOURCE_S3;

	if (!cfg_str) {
		erofs_err("s3: missing parameter");
		return -EINVAL;
	}

	s3cfg.url_style = S3EROFS_URL_STYLE_VIRTUAL_HOST;
	s3cfg.sig = S3EROFS_SIGNATURE_VERSION_2;

	p = strchr(cfg_str, ',');
	if (p) {
		s3cfg.endpoint = strndup(cfg_str, p - cfg_str);
	} else {
		s3cfg.endpoint = strdup(cfg_str);
		return 0;
	}

	opt = p + 1;
	while (opt) {
		q = strchr(opt, ',');
		if (q)
			*q = '\0';

		if ((p = strstr(opt, "passwd_file="))) {
			p += sizeof("passwd_file=") - 1;
			ret = mkfs_parse_s3_cfg_passwd(p, s3cfg.access_key,
						       s3cfg.secret_key);
			if (ret)
				return ret;
		} else if ((p = strstr(opt, "urlstyle="))) {
			p += sizeof("urlstyle=") - 1;
			if (strncmp(p, "vhost", 5) == 0) {
				s3cfg.url_style = S3EROFS_URL_STYLE_VIRTUAL_HOST;
			} else if (strncmp(p, "path", 4) == 0) {
				s3cfg.url_style = S3EROFS_URL_STYLE_PATH;
			} else {
				erofs_err("invalid S3 addressing style %s", p);
				return -EINVAL;
			}
		} else if ((p = strstr(opt, "sig="))) {
			p += strlen("sig=");
			if (strncmp(p, "4", 1) == 0) {
				s3cfg.sig = S3EROFS_SIGNATURE_VERSION_4;
			} else if (strncmp(p, "2", 1) == 0) {
				s3cfg.sig = S3EROFS_SIGNATURE_VERSION_2;
			} else {
				erofs_err("invalid AWS signature version %s", p);
				return -EINVAL;
			}
		} else if ((p = strstr(opt, "region="))) {
			p += strlen("region=");
			opt = strchr(cfg_str, ',');
			s3cfg.region = opt ? strndup(p, opt - p) : strdup(p);
		} else {
			erofs_err("invalid --s3 option %s", opt);
			return -EINVAL;
		}

		opt = q ? q + 1 : NULL;
	}

	if (s3cfg.sig == S3EROFS_SIGNATURE_VERSION_4 && !s3cfg.region) {
		erofs_err("invalid --s3: using sig=4 requires region provided");
		return -EINVAL;
	}

	return 0;
}
#endif

#ifdef OCIEROFS_ENABLED
/*
 * mkfs_parse_oci_options - Parse comma-separated OCI options string
 * @cfg: OCI configuration structure to update
 * @options_str: comma-separated options string
 *
 * Parse OCI options string containing comma-separated key=value pairs.
 *
 * Supported options include f|i, platform, blob|layer, username, password,
 * and zinfo.
 *
 * Return: 0 on success, negative errno on failure
 */
static int mkfs_parse_oci_options(struct ocierofs_config *oci_cfg, char *options_str)
{
	char *opt, *q, *p;
	long idx;

	if (!options_str)
		return 0;

	opt = options_str;
	q = strchr(opt, ',');
	if (q)
		*q = '\0';
	if (!strcmp(opt, "i") || !strcmp(opt, "f")) {
		mkfs_oci_tarindex_mode = (*opt == 'i');
		opt = q ? q + 1 : NULL;
	} else if (q) {
		*q = ',';
	}

	while (opt) {
		q = strchr(opt, ',');
		if (q)
			*q = '\0';


		p = strstr(opt, "platform=");
		if (p) {
			p += strlen("platform=");
			free(oci_cfg->platform);
			oci_cfg->platform = strdup(p);
			if (!oci_cfg->platform)
				return -ENOMEM;
		} else {
			p = strstr(opt, "blob=");
			if (p) {
				p += strlen("blob=");
				free(oci_cfg->blob_digest);

				if (oci_cfg->layer_index >= 0) {
					erofs_err("invalid --oci: blob and layer cannot be set together");
					return -EINVAL;
				}

				if (!strncmp(p, "sha256:", 7)) {
					oci_cfg->blob_digest = strdup(p);
					if (!oci_cfg->blob_digest)
						return -ENOMEM;
				} else if (asprintf(&oci_cfg->blob_digest, "sha256:%s", p) < 0) {
					return -ENOMEM;
				}
			} else {
				p = strstr(opt, "layer=");
				if (p) {
					p += strlen("layer=");
					if (oci_cfg->blob_digest) {
						erofs_err("invalid --oci: layer and blob cannot be set together");
						return -EINVAL;
					}
					idx = strtol(p, NULL, 10);
					if (idx < 0)
						return -EINVAL;
					oci_cfg->layer_index = (int)idx;
				} else {
					p = strstr(opt, "username=");
					if (p) {
						p += strlen("username=");
						free(oci_cfg->username);
						oci_cfg->username = strdup(p);
						if (!oci_cfg->username)
							return -ENOMEM;
					} else {
						p = strstr(opt, "password=");
						if (p) {
							p += strlen("password=");
							free(oci_cfg->password);
							oci_cfg->password = strdup(p);
							if (!oci_cfg->password)
								return -ENOMEM;
						} else {
							erofs_err("mkfs: invalid --oci value %s", opt);
							return -EINVAL;
						}
					}
				}
			}
		}

		opt = q ? q + 1 : NULL;
	}

	return 0;
}
#endif

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

	switch (source_mode) {
	case EROFS_MKFS_SOURCE_LOCALDIR:
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
			source_mode = EROFS_MKFS_SOURCE_REBUILD;
		}
		break;
	case EROFS_MKFS_SOURCE_TAR:
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
		break;
#ifdef S3EROFS_ENABLED
	case EROFS_MKFS_SOURCE_S3:
		cfg.c_src_path = strdup(argv[optind++]);
		if (!cfg.c_src_path)
			return -ENOMEM;
		break;
#endif
#ifdef OCIEROFS_ENABLED
	case EROFS_MKFS_SOURCE_OCI:
		if (optind < argc) {
			cfg.c_src_path = strdup(argv[optind++]);
			if (!cfg.c_src_path)
				return -ENOMEM;
		} else {
			erofs_err("missing OCI source argument");
			return -EINVAL;
		}
		break;
#endif
	default:
		erofs_err("unexpected source_mode: %d", source_mode);
		return -EINVAL;
	}

	if (source_mode == EROFS_MKFS_SOURCE_REBUILD) {
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

static int mkfs_parse_options_cfg(struct erofs_importer_params *params,
				  int argc, char *argv[])
{
	bool has_timestamp = false;
	bool quiet = false;
	char *endptr;
	int opt, err;
	long i;

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
			mkfs_blkszbits = ilog2(i);
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
			mkfscfg.inlinexattr_tolerance = i;
			break;

		case 'E':
			opt = parse_extended_opts(params, optarg);
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
			params->fixed_uid = strtoul(optarg, &endptr, 0);
			if (params->fixed_uid == -1 || *endptr != '\0') {
				erofs_err("invalid uid %s", optarg);
				return -EINVAL;
			}
			break;
		case 6:
			params->fixed_gid = strtoul(optarg, &endptr, 0);
			if (params->fixed_gid == -1 || *endptr != '\0') {
				erofs_err("invalid gid %s", optarg);
				return -EINVAL;
			}
			break;
		case 7:
			params->fixed_uid = params->fixed_gid = 0;
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
			params->ignore_mtime = true;
			break;
		case 15:
			params->ignore_mtime = false;
			break;
		case 16:
			errno = 0;
			params->uid_offset = strtoul(optarg, &endptr, 0);
			if (errno || *endptr != '\0') {
				erofs_err("invalid uid offset %s", optarg);
				return -EINVAL;
			}
			break;
		case 17:
			errno = 0;
			params->gid_offset = strtoul(optarg, &endptr, 0);
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
			params->ovlfs_strip = !optarg || !strcmp(optarg, "1");
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
			err = mkfs_apply_zfeature_bits(params, i);
			if (err)
				return err;
			break;
		case 522:
		case 523:
			if (!optarg || !strcmp(optarg, "data")) {
				dataimport_mode = EROFS_MKFS_DATA_IMPORT_FULLDATA;
			} else if (!strcmp(optarg, "rvsp")) {
				dataimport_mode = EROFS_MKFS_DATA_IMPORT_RVSP;
			} else if (!strcmp(optarg, "0")) {
				dataimport_mode = EROFS_MKFS_DATA_IMPORT_ZEROFILL;
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
			params->hard_dereference = true;
			break;
#ifdef EROFS_MT_ENABLED
		case 530:
			params->mt_async_queue_limit = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid async-queue-limit %s", optarg);
				return -EINVAL;
			}
			break;
#endif
		case 531:
			params->fsalignblks = strtoul(optarg, &endptr, 0);
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
#ifdef S3EROFS_ENABLED
		case 533:
			err = mkfs_parse_s3_cfg(optarg);
			if (err)
				return err;
			break;
#endif
#ifdef OCIEROFS_ENABLED
		case 534: {
			source_mode = EROFS_MKFS_SOURCE_OCI;
			err = mkfs_parse_oci_options(&ocicfg, optarg);
			if (err)
				return err;
			break;
		}
#endif
		case 535:
			if (optarg)
				mkfs_aws_zinfo_file = strdup(optarg);
			tarerofs_decoder = EROFS_IOS_DECODER_GZRAN;
			break;
		case 536:
			if (!optarg || strcmp(optarg, "1")) {
				params->compress_dir = true;
				params->grouped_dirdata = true;
			} else {
				params->compress_dir = false;
			}
			break;
		case 537:
			if (!optarg || strcmp(optarg, "1"))
				mkfscfg.inode_metazone = true;
			else
				mkfscfg.inode_metazone = false;
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

	if (cfg.c_blobdev_path && cfg.c_chunkbits < mkfs_blkszbits) {
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
	} else if (source_mode != EROFS_MKFS_SOURCE_TAR) {
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
		if (pclustersize_max < (1U << mkfs_blkszbits) ||
		    pclustersize_max % (1U << mkfs_blkszbits)) {
			erofs_err("invalid physical clustersize %u",
				  pclustersize_max);
			return -EINVAL;
		}
		params->pclusterblks_max = pclustersize_max >> mkfs_blkszbits;
		params->pclusterblks_def = params->pclusterblks_max;
	}
	if (cfg.c_chunkbits && cfg.c_chunkbits < mkfs_blkszbits) {
		erofs_err("chunksize %u must be larger than block size",
			  1u << cfg.c_chunkbits);
		return -EINVAL;
	}

	if (pclustersize_packed) {
		if (pclustersize_packed < (1U << mkfs_blkszbits) ||
		    pclustersize_packed % (1U << mkfs_blkszbits)) {
			erofs_err("invalid pcluster size for the packed file %u",
				  pclustersize_packed);
			return -EINVAL;
		}
		params->pclusterblks_packed = pclustersize_packed >> mkfs_blkszbits;
	}

	if (pclustersize_metabox >= 0) {
		if (pclustersize_metabox &&
		    (pclustersize_metabox < (1U << mkfs_blkszbits) ||
		     pclustersize_metabox % (1U << mkfs_blkszbits))) {
			erofs_err("invalid pcluster size %u for the metabox inode",
				  pclustersize_metabox);
			return -EINVAL;
		}
		params->pclusterblks_metabox = pclustersize_metabox >> mkfs_blkszbits;
		cfg.c_mkfs_metabox_algid = metabox_algorithmid;
		erofs_sb_set_metabox(&g_sbi);
	}

	if (has_timestamp && cfg.c_timeinherit == TIMESTAMP_UNSPECIFIED)
		cfg.c_timeinherit = TIMESTAMP_FIXED;
	return 0;
}

static void erofs_mkfs_default_options(struct erofs_importer_params *params)
{
	cfg.c_showprogress = true;
	cfg.c_xattr_name_filter = true;
#ifdef EROFS_MT_ENABLED
	cfg.c_mt_workers = erofs_get_available_processors();
	cfg.c_mkfs_segment_size = 16ULL * 1024 * 1024;
#endif
	mkfs_blkszbits = ilog2(min_t(u32, getpagesize(), EROFS_MAX_BLOCK_SIZE));
	params->pclusterblks_max = 1U;
	params->pclusterblks_def = 1U;
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
		uuid_str, g_sbi.total_blocks | 0ULL, 1U << mkfs_blkszbits,
		g_sbi.inos | 0ULL,
		incr, erofs_total_metablocks(g_sbi.bmgr) | 0ULL,
		incr, g_sbi.saved_by_deduplication | 0ULL);
}

int main(int argc, char **argv)
{
	struct erofs_importer_params importer_params;
	struct erofs_importer importer = {
		.params = &importer_params,
		.sbi = &g_sbi,
	};
	struct erofs_inode *root = NULL;
	bool tar_index_512b = false;
	struct timeval t;
	FILE *blklst = NULL;
	s64 mkfs_time = 0;
	int err;
	u32 crc;

	err = liberofs_global_init();
	if (err)
		return 1;
	erofs_importer_preset(&importer_params);
	erofs_mkfs_default_options(&importer_params);

	err = mkfs_parse_options_cfg(&importer_params, argc, argv);
	erofs_show_progs(argc, argv);
	if (err) {
		if (err == -EINVAL)
			fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		goto exit;
	}

	err = parse_source_date_epoch();
	if (err) {
		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		goto exit;
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

	err = erofs_dev_open(&g_sbi, cfg.c_img_path, O_RDWR |
				(incremental_mode ? 0 : O_TRUNC));
	if (err) {
		fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		goto exit;
	}

#ifdef WITH_ANDROID
	if (cfg.fs_config_file &&
	    load_canned_fs_config(cfg.fs_config_file) < 0) {
		erofs_err("failed to load fs config %s", cfg.fs_config_file);
		goto exit;
	}
#endif
	erofs_show_config();

#ifndef NDEBUG
	if (cfg.c_random_pclusterblks)
		srand(time(NULL));
#endif
	if (source_mode == EROFS_MKFS_SOURCE_TAR) {
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
			mkfs_blkszbits = 9;
			tar_index_512b = true;
		}
	} else if (source_mode == EROFS_MKFS_SOURCE_REBUILD) {
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
		mkfs_blkszbits = src->blkszbits;
	} else if (mkfs_oci_tarindex_mode) {
		mkfs_blkszbits = 9;
		tar_index_512b = true;
	}

	if (!incremental_mode)
		err = erofs_mkfs_format_fs(&g_sbi, mkfs_blkszbits, 0,
					   mkfscfg.inode_metazone);
	else
		err = erofs_mkfs_load_fs(&g_sbi, 0);
	if (err)
		goto exit;

	/* Use the user-defined UUID or generate one for clean builds */
	if (valid_fixeduuid)
		memcpy(g_sbi.uuid, fixeduuid, sizeof(g_sbi.uuid));
	else if (!incremental_mode)
		erofs_uuid_generate(g_sbi.uuid);

	if ((source_mode == EROFS_MKFS_SOURCE_TAR && !erofstar.index_mode) ||
	    (source_mode == EROFS_MKFS_SOURCE_S3) ||
	    (source_mode == EROFS_MKFS_SOURCE_OCI)) {
		err = erofs_diskbuf_init(1);
		if (err) {
			erofs_err("failed to initialize diskbuf: %s",
				   strerror(-err));
			goto exit;
		}
	}

	err = erofs_load_compress_hints(&importer, &g_sbi);
	if (err) {
		erofs_err("failed to load compress hints %s",
			  cfg.c_compress_hints_file);
		goto exit;
	}

	if (mkfscfg.inlinexattr_tolerance < 0)
		importer_params.no_xattrs = true;
	importer_params.source = cfg.c_src_path;
	importer_params.no_datainline = mkfs_no_datainline;
	importer_params.dot_omitted = mkfs_dot_omitted;
	err = erofs_importer_init(&importer);
	if (err)
		goto exit;

	if (importer_params.dedupe == EROFS_DEDUPE_FORCE_ON) {
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

	cfg.c_dedupe = importer_params.dedupe;
	if (cfg.c_chunkbits) {
		err = erofs_blob_init(cfg.c_blobdev_path, 1 << cfg.c_chunkbits);
		if (err)
			goto exit;
	}

	if (tar_index_512b || cfg.c_blobdev_path) {
		err = erofs_mkfs_init_devices(&g_sbi, 1);
		if (err) {
			erofs_err("failed to generate device table: %s",
				  erofs_strerror(err));
			goto exit;
		}
	}

	if (source_mode == EROFS_MKFS_SOURCE_LOCALDIR) {
		err = erofs_load_shared_xattrs_from_path(&g_sbi, cfg.c_src_path,
						mkfscfg.inlinexattr_tolerance);
		if (err) {
			erofs_err("failed to load shared xattrs: %s",
				  erofs_strerror(err));
			goto exit;
		}

		if (cfg.c_extra_ea_name_prefixes)
			erofs_xattr_flush_name_prefixes(&importer,
							mkfs_plain_xattr_pfx);

		root = erofs_new_inode(&g_sbi);
		if (IS_ERR(root)) {
			err = PTR_ERR(root);
			goto exit;
		}
	} else {
		root = erofs_rebuild_make_root(&g_sbi);
		if (IS_ERR(root)) {
			err = PTR_ERR(root);
			goto exit;
		}
	}

	importer.root = root;
	if (source_mode == EROFS_MKFS_SOURCE_TAR) {
		while (!(err = tarerofs_parse_tar(&importer, &erofstar)))
			;
	} else if (source_mode == EROFS_MKFS_SOURCE_REBUILD) {
		err = erofs_mkfs_rebuild_load_trees(root);
#ifdef S3EROFS_ENABLED
	} else if (source_mode == EROFS_MKFS_SOURCE_S3) {
		if (!s3cfg.access_key[0] && getenv("AWS_ACCESS_KEY_ID")) {
			strncpy(s3cfg.access_key, getenv("AWS_ACCESS_KEY_ID"),
				sizeof(s3cfg.access_key));
			s3cfg.access_key[S3_ACCESS_KEY_LEN] = '\0';
		}
		if (!s3cfg.secret_key[0] && getenv("AWS_SECRET_ACCESS_KEY")) {
			strncpy(s3cfg.secret_key, getenv("AWS_SECRET_ACCESS_KEY"),
				sizeof(s3cfg.secret_key));
			s3cfg.secret_key[S3_SECRET_KEY_LEN] = '\0';
		}

		if (incremental_mode ||
		    dataimport_mode == EROFS_MKFS_DATA_IMPORT_RVSP)
			err = -EOPNOTSUPP;
		else
			err = s3erofs_build_trees(&importer, &s3cfg,
						  cfg.c_src_path,
				dataimport_mode == EROFS_MKFS_DATA_IMPORT_ZEROFILL);
#endif
#ifdef OCIEROFS_ENABLED
		} else if (source_mode == EROFS_MKFS_SOURCE_OCI) {
			ocicfg.image_ref = cfg.c_src_path;
			if (mkfs_oci_tarindex_mode)
				ocicfg.tarindex_path = strdup(cfg.c_src_path);
			if (!ocicfg.zinfo_path)
				ocicfg.zinfo_path = mkfs_aws_zinfo_file;

			if (incremental_mode ||
			    dataimport_mode == EROFS_MKFS_DATA_IMPORT_RVSP ||
			    dataimport_mode == EROFS_MKFS_DATA_IMPORT_ZEROFILL)
				err = -EOPNOTSUPP;
			else
				err = ocierofs_build_trees(&importer, &ocicfg);
			if (err)
				goto exit;
#endif
	}
	if (err < 0)
		goto exit;

	err = erofs_importer_load_tree(&importer,
				       source_mode != EROFS_MKFS_SOURCE_LOCALDIR,
				       incremental_mode);
	if (err)
		goto exit;

	if (tar_index_512b) {
		if (!g_sbi.extra_devices) {
			DBG_BUGON(1);
		} else {
			if (source_mode != EROFS_MKFS_SOURCE_OCI) {
				if (cfg.c_src_path)
					g_sbi.devs[0].src_path = strdup(cfg.c_src_path);
				g_sbi.devs[0].blocks =
					BLK_ROUND_UP(&g_sbi, erofstar.offset);
			}
		}
	}

	if (erofstar.index_mode || cfg.c_chunkbits || g_sbi.extra_devices) {
		err = erofs_mkfs_dump_blobs(&g_sbi);
		if (err)
			goto exit;
	}

	err = erofs_importer_flush_all(&importer);
	if (err)
		goto exit;
	erofs_iput(root);
	root = NULL;

	err = erofs_writesb(&g_sbi);
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
	z_erofs_dedupe_exit();
	blklst = erofs_blocklist_close();
	if (blklst)
		fclose(blklst);
	erofs_dev_close(&g_sbi);
	erofs_cleanup_compress_hints();
	erofs_cleanup_exclude_rules();
	if (cfg.c_chunkbits || source_mode == EROFS_MKFS_SOURCE_REBUILD)
		erofs_blob_exit();
	erofs_xattr_cleanup_name_prefixes();
	erofs_rebuild_cleanup();
	erofs_diskbuf_exit();
	if (!err && source_mode == EROFS_MKFS_SOURCE_TAR) {
		if (mkfs_aws_zinfo_file) {
			struct erofs_vfile vf;
			int fd;

			fd = open(mkfs_aws_zinfo_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (fd < 0) {
				err = -errno;
			} else {
				vf = (struct erofs_vfile){ .fd = fd };
				err = erofs_gzran_builder_export_zinfo(erofstar.ios.gb, &vf);
			}
		}
		erofs_iostream_close(&erofstar.ios);
		if (erofstar.ios.dumpfd >= 0)
			close(erofstar.ios.dumpfd);
	}
	erofs_importer_exit(&importer);

	if (err) {
		erofs_err("\tCould not format the device : %s\n",
			  erofs_strerror(err));
		err = 1;
	} else {
		erofs_update_progressinfo("Build completed.\n");
		erofs_mkfs_showsummaries();
	}
	erofs_put_super(&g_sbi);
	liberofs_global_exit();
	return err;
}
