// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2021 Google LLC
 * Author: Daeho Jeong <daehojeong@google.com>
 */
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <utime.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include "erofs/print.h"
#include "erofs/compress.h"
#include "erofs/decompress.h"
#include "erofs/dir.h"
#include "erofs/xattr.h"
#include "../lib/compressor.h"
#include "erofs/fragments.h"

static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid);

struct erofsfsck_dirstack {
	erofs_nid_t dirs[PATH_MAX];
	int top;
};

struct erofsfsck_cfg {
	struct erofsfsck_dirstack dirstack;
	u64 physical_blocks;
	u64 logical_blocks;
	char *extract_path;
	size_t extract_pos;
	mode_t umask;
	bool superuser;
	bool corrupted;
	bool print_comp_ratio;
	bool check_decomp;
	bool force;
	bool overwrite;
	bool preserve_owner;
	bool preserve_perms;
	bool dump_xattrs;
	bool nosbcrc;
};
static struct erofsfsck_cfg fsckcfg;

static struct option long_options[] = {
	{"version", no_argument, 0, 'V'},
	{"help", no_argument, 0, 'h'},
	{"extract", optional_argument, 0, 2},
	{"device", required_argument, 0, 3},
	{"force", no_argument, 0, 4},
	{"overwrite", no_argument, 0, 5},
	{"preserve", no_argument, 0, 6},
	{"preserve-owner", no_argument, 0, 7},
	{"preserve-perms", no_argument, 0, 8},
	{"no-preserve", no_argument, 0, 9},
	{"no-preserve-owner", no_argument, 0, 10},
	{"no-preserve-perms", no_argument, 0, 11},
	{"offset", required_argument, 0, 12},
	{"xattrs", no_argument, 0, 13},
	{"no-xattrs", no_argument, 0, 14},
	{"no-sbcrc", no_argument, 0, 512},
	{0, 0, 0, 0},
};

#define NR_HARDLINK_HASHTABLE	16384

struct erofsfsck_hardlink_entry {
	struct list_head list;
	erofs_nid_t nid;
	char *path;
};

static struct list_head erofsfsck_link_hashtable[NR_HARDLINK_HASHTABLE];

static void print_available_decompressors(FILE *f, const char *delim)
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
	//	"         1         2         3         4         5         6         7         8  "
	//	"12345678901234567890123456789012345678901234567890123456789012345678901234567890\n"
	printf(
		"Usage: %s [OPTIONS] IMAGE\n"
		"Check erofs filesystem compatibility and integrity of IMAGE.\n"
		"\n"
		"This version of fsck.erofs is capable of checking images that use any of the\n"
		"following algorithms: ", argv[0]);
	print_available_decompressors(stdout, ", ");
	printf("\n"
		"General options:\n"
		" -V, --version          print the version number of fsck.erofs and exit\n"
		" -h, --help             display this help and exit\n"
		"\n"
		" -d<0-9>                set output verbosity; 0=quiet, 9=verbose (default=%i)\n"
		" -p                     print total compression ratio of all files\n"
		" --device=X             specify an extra device to be used together\n"
		" --extract[=X]          check if all files are well encoded, optionally\n"
		"                        extract to X\n"
		" --offset=#             skip # bytes at the beginning of IMAGE\n"
		" --no-sbcrc             bypass the superblock checksum verification\n"
		" --[no-]xattrs          whether to dump extended attributes (default off)\n"
		"\n"
		" -a, -A, -y             no-op, for compatibility with fsck of other filesystems\n"
		"\n"
		"Extraction options (--extract=X is required):\n"
		" --force                allow extracting to root\n"
		" --overwrite            overwrite files that already exist\n"
		" --[no-]preserve        same as --[no-]preserve-owner --[no-]preserve-perms\n"
		" --[no-]preserve-owner  whether to preserve the ownership from the\n"
		"                        filesystem (default for superuser), or to extract as\n"
		"                        yourself (default for ordinary users)\n"
		" --[no-]preserve-perms  whether to preserve the exact permissions from the\n"
		"                        filesystem without applying umask (default for\n"
		"                        superuser), or to modify the permissions by applying\n"
		"                        umask (default for ordinary users)\n",
		EROFS_WARN);
}

static void erofsfsck_print_version(void)
{
	printf("fsck.erofs (erofs-utils) %s\navailable decompressors: ",
	       cfg.c_version);
	print_available_decompressors(stdout, ", ");
}

static int erofsfsck_parse_options_cfg(int argc, char **argv)
{
	char *endptr;
	int opt, ret;
	bool has_opt_preserve = false;

	while ((opt = getopt_long(argc, argv, "Vd:phaAy",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'V':
			erofsfsck_print_version();
			exit(0);
		case 'd':
			ret = atoi(optarg);
			if (ret < EROFS_MSG_MIN || ret > EROFS_MSG_MAX) {
				erofs_err("invalid debug level %d", ret);
				return -EINVAL;
			}
			cfg.c_dbg_lvl = ret;
			break;
		case 'p':
			fsckcfg.print_comp_ratio = true;
			break;
		case 'h':
			usage(argc, argv);
			exit(0);
		case 'a':
		case 'A':
		case 'y':
			break;
		case 2:
			fsckcfg.check_decomp = true;
			if (optarg) {
				size_t len = strlen(optarg);

				if (len == 0) {
					erofs_err("empty value given for --extract=X");
					return -EINVAL;
				}

				/* remove trailing slashes except root */
				while (len > 1 && optarg[len - 1] == '/')
					len--;

				if (len >= PATH_MAX) {
					erofs_err("target directory name too long!");
					return -ENAMETOOLONG;
				}

				fsckcfg.extract_path = malloc(PATH_MAX);
				if (!fsckcfg.extract_path)
					return -ENOMEM;
				strncpy(fsckcfg.extract_path, optarg, len);
				fsckcfg.extract_path[len] = '\0';
				/* if path is root, start writing from position 0 */
				if (len == 1 && fsckcfg.extract_path[0] == '/')
					len = 0;
				fsckcfg.extract_pos = len;
			}
			break;
		case 3:
			ret = erofs_blob_open_ro(&g_sbi, optarg);
			if (ret)
				return ret;
			++g_sbi.extra_devices;
			break;
		case 4:
			fsckcfg.force = true;
			break;
		case 5:
			fsckcfg.overwrite = true;
			break;
		case 6:
			fsckcfg.preserve_owner = fsckcfg.preserve_perms = true;
			has_opt_preserve = true;
			break;
		case 7:
			fsckcfg.preserve_owner = true;
			has_opt_preserve = true;
			break;
		case 8:
			fsckcfg.preserve_perms = true;
			has_opt_preserve = true;
			break;
		case 9:
			fsckcfg.preserve_owner = fsckcfg.preserve_perms = false;
			has_opt_preserve = true;
			break;
		case 10:
			fsckcfg.preserve_owner = false;
			has_opt_preserve = true;
			break;
		case 11:
			fsckcfg.preserve_perms = false;
			has_opt_preserve = true;
			break;
		case 12:
			g_sbi.bdev.offset = strtoull(optarg, &endptr, 0);
			if (*endptr != '\0') {
				erofs_err("invalid disk offset %s", optarg);
				return -EINVAL;
			}
			break;
		case 13:
			fsckcfg.dump_xattrs = true;
			break;
		case 14:
			fsckcfg.dump_xattrs = false;
			break;
		case 512:
			fsckcfg.nosbcrc = true;
			break;
		default:
			return -EINVAL;
		}
	}

	if (fsckcfg.extract_path) {
		if (!fsckcfg.extract_pos && !fsckcfg.force) {
			erofs_err("--extract=/ must be used together with --force");
			return -EINVAL;
		}
	} else {
		if (fsckcfg.force) {
			erofs_err("--force must be used together with --extract=X");
			return -EINVAL;
		}
		if (fsckcfg.overwrite) {
			erofs_err("--overwrite must be used together with --extract=X");
			return -EINVAL;
		}
		if (has_opt_preserve) {
			erofs_err("--[no-]preserve[-owner/-perms] must be used together with --extract=X");
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
		erofs_err("unexpected argument: %s", argv[optind]);
		return -EINVAL;
	}
	return 0;
}

static void erofsfsck_set_attributes(struct erofs_inode *inode, char *path)
{
	int ret;

	/* don't apply attributes when fsck is used without extraction */
	if (!fsckcfg.extract_path)
		return;

#ifdef HAVE_UTIMENSAT
	if (utimensat(AT_FDCWD, path, (struct timespec []) {
				[0] = { .tv_sec = inode->i_mtime,
					.tv_nsec = inode->i_mtime_nsec },
				[1] = { .tv_sec = inode->i_mtime,
					.tv_nsec = inode->i_mtime_nsec },
			}, AT_SYMLINK_NOFOLLOW) < 0)
#else
	if (utime(path, &((struct utimbuf){.actime = inode->i_mtime,
					   .modtime = inode->i_mtime})) < 0)
#endif
		erofs_warn("failed to set times: %s", path);

	if (fsckcfg.preserve_owner) {
		ret = lchown(path, inode->i_uid, inode->i_gid);
		if (ret < 0)
			erofs_warn("failed to change ownership: %s", path);
	}

	if (!S_ISLNK(inode->i_mode)) {
		if (fsckcfg.preserve_perms)
			ret = chmod(path, inode->i_mode);
		else
			ret = chmod(path, inode->i_mode & ~fsckcfg.umask);
		if (ret < 0)
			erofs_warn("failed to set permissions: %s", path);
	}
}

static int erofs_verify_xattr(struct erofs_inode *inode)
{
	struct erofs_sb_info *sbi = inode->sbi;
	unsigned int xattr_hdr_size = sizeof(struct erofs_xattr_ibody_header);
	unsigned int xattr_entry_size = sizeof(struct erofs_xattr_entry);
	erofs_off_t addr;
	unsigned int ofs, xattr_shared_count;
	struct erofs_xattr_ibody_header *ih;
	struct erofs_xattr_entry *entry;
	int i, remaining = inode->xattr_isize, ret = 0;
	char buf[EROFS_MAX_BLOCK_SIZE];

	if (inode->xattr_isize == xattr_hdr_size) {
		erofs_err("xattr_isize %d of nid %llu is not supported yet",
			  inode->xattr_isize, inode->nid | 0ULL);
		ret = -EFSCORRUPTED;
		goto out;
	} else if (inode->xattr_isize < xattr_hdr_size) {
		if (inode->xattr_isize) {
			erofs_err("bogus xattr ibody @ nid %llu",
				  inode->nid | 0ULL);
			ret = -EFSCORRUPTED;
			goto out;
		}
	}

	addr = erofs_iloc(inode) + inode->inode_isize;
	ret = erofs_dev_read(sbi, 0, buf, addr, xattr_hdr_size);
	if (ret < 0) {
		erofs_err("failed to read xattr header @ nid %llu: %d",
			  inode->nid | 0ULL, ret);
		goto out;
	}
	ih = (struct erofs_xattr_ibody_header *)buf;
	xattr_shared_count = ih->h_shared_count;

	ofs = erofs_blkoff(sbi, addr) + xattr_hdr_size;
	addr += xattr_hdr_size;
	remaining -= xattr_hdr_size;
	for (i = 0; i < xattr_shared_count; ++i) {
		if (ofs >= erofs_blksiz(sbi)) {
			if (ofs != erofs_blksiz(sbi)) {
				erofs_err("unaligned xattr entry in xattr shared area @ nid %llu",
					  inode->nid | 0ULL);
				ret = -EFSCORRUPTED;
				goto out;
			}
			ofs = 0;
		}
		ofs += xattr_entry_size;
		addr += xattr_entry_size;
		remaining -= xattr_entry_size;
	}

	while (remaining > 0) {
		unsigned int entry_sz;

		ret = erofs_dev_read(sbi, 0, buf, addr, xattr_entry_size);
		if (ret) {
			erofs_err("failed to read xattr entry @ nid %llu: %d",
				  inode->nid | 0ULL, ret);
			goto out;
		}

		entry = (struct erofs_xattr_entry *)buf;
		entry_sz = erofs_xattr_entry_size(entry);
		if (remaining < entry_sz) {
			erofs_err("xattr on-disk corruption: xattr entry beyond xattr_isize @ nid %llu",
				  inode->nid | 0ULL);
			ret = -EFSCORRUPTED;
			goto out;
		}
		addr += entry_sz;
		remaining -= entry_sz;
	}
out:
	return ret;
}

static int erofsfsck_dump_xattrs(struct erofs_inode *inode)
{
	static bool ignore_xattrs = false;
	char *keylst, *key;
	ssize_t kllen;
	int ret;

	kllen = erofs_listxattr(inode, NULL, 0);
	if (kllen <= 0)
		return kllen;
	keylst = malloc(kllen);
	if (!keylst)
		return -ENOMEM;
	ret = erofs_listxattr(inode, keylst, kllen);
	if (ret != kllen) {
		erofs_err("failed to list xattrs @ nid %llu",
			  inode->nid | 0ULL);
		ret = -EINVAL;
		goto out;
	}
	ret = 0;
	for (key = keylst; key < keylst + kllen; key += strlen(key) + 1) {
		unsigned int index, len;
		void *value = NULL;
		size_t size = 0;

		ret = erofs_getxattr(inode, key, NULL, 0);
		if (ret <= 0) {
			DBG_BUGON(1);
			erofs_err("failed to get xattr value size of `%s` @ nid %llu",
				  key, inode->nid | 0ULL);
			break;
		}
		size = ret;
		value = malloc(size);
		if (!value) {
			ret = -ENOMEM;
			break;
		}
		ret = erofs_getxattr(inode, key, value, size);
		if (ret < 0) {
			erofs_err("failed to get xattr `%s` @ nid %llu, because of `%s`", key,
				  inode->nid | 0ULL, erofs_strerror(ret));
			free(value);
			break;
		}
		if (fsckcfg.extract_path)
#ifdef HAVE_LSETXATTR
			ret = lsetxattr(fsckcfg.extract_path, key, value, size,
					0);
#elif defined(__APPLE__)
			ret = setxattr(fsckcfg.extract_path, key, value, size,
				       0, XATTR_NOFOLLOW);
#else
			ret = -EOPNOTSUPP;
#endif
		else
			ret = 0;
		free(value);
		if (ret == -EPERM && !fsckcfg.superuser) {
			if (__erofs_unlikely(!erofs_xattr_prefix_matches(key,
					&index, &len))) {
				erofs_err("failed to match the prefix of `%s` @ nid %llu",
					  key, inode->nid | 0ULL);
				ret = -EINVAL;
				break;
			}
			if (index != EROFS_XATTR_INDEX_USER) {
				if (!ignore_xattrs) {
					erofs_warn("ignored xattr `%s` @ nid %llu, due to non-superuser",
						   key, inode->nid | 0ULL);
					ignore_xattrs = true;
				}
				ret = 0;
				continue;
			}

		}
		if (ret) {
			erofs_err("failed to set xattr `%s` @ nid %llu because of `%s`",
				  key, inode->nid | 0ULL, erofs_strerror(ret));
			break;
		}
	}
out:
	free(keylst);
	return ret;
}

static int erofs_verify_inode_data(struct erofs_inode *inode, int outfd)
{
	struct erofs_map_blocks map = {
		.buf = __EROFS_BUF_INITIALIZER,
	};
	bool needdecode = fsckcfg.check_decomp && !erofs_is_packed_inode(inode);
	int ret = 0;
	bool compressed;
	erofs_off_t pos = 0;
	u64 pchunk_len = 0;
	unsigned int raw_size = 0, buffer_size = 0;
	char *raw = NULL, *buffer = NULL;

	erofs_dbg("verify data chunk of nid(%llu): type(%d)",
		  inode->nid | 0ULL, inode->datalayout);

	compressed = erofs_inode_is_data_compressed(inode->datalayout);
	while (pos < inode->i_size) {
		unsigned int alloc_rawsize;

		map.m_la = pos;
		ret = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_FIEMAP);
		if (ret)
			goto out;

		if (!compressed && map.m_llen != map.m_plen) {
			erofs_err("broken chunk length m_la %" PRIu64 " m_llen %" PRIu64 " m_plen %" PRIu64,
				  map.m_la, map.m_llen, map.m_plen);
			ret = -EFSCORRUPTED;
			goto out;
		}

		/* the last lcluster can be divided into 3 parts */
		if (map.m_la + map.m_llen > inode->i_size)
			map.m_llen = inode->i_size - map.m_la;

		pchunk_len += map.m_plen;
		pos += map.m_llen;

		/* should skip decomp? */
		if (map.m_la >= inode->i_size || !needdecode)
			continue;

		if (outfd >= 0 && !(map.m_flags & EROFS_MAP_MAPPED)) {
			ret = lseek(outfd, map.m_llen, SEEK_CUR);
			if (ret < 0) {
				ret = -errno;
				goto out;
			}
			continue;
		}

		if (map.m_plen > Z_EROFS_PCLUSTER_MAX_SIZE) {
			if (compressed && !(map.m_flags & __EROFS_MAP_FRAGMENT)) {
				erofs_err("invalid pcluster size %" PRIu64 " @ offset %" PRIu64 " of nid %" PRIu64,
					  map.m_plen, map.m_la,
					  inode->nid | 0ULL);
				ret = -EFSCORRUPTED;
				goto out;
			}
			alloc_rawsize = Z_EROFS_PCLUSTER_MAX_SIZE;
		} else {
			alloc_rawsize = map.m_plen;
		}

		if (alloc_rawsize > raw_size) {
			char *newraw = realloc(raw, alloc_rawsize);

			if (!newraw) {
				ret = -ENOMEM;
				goto out;
			}
			raw = newraw;
			raw_size = alloc_rawsize;
		}

		if (compressed) {
			if (map.m_llen > buffer_size) {
				char *newbuffer;

				buffer_size = map.m_llen;
				newbuffer = realloc(buffer, buffer_size);
				if (!newbuffer) {
					ret = -ENOMEM;
					goto out;
				}
				buffer = newbuffer;
			}
			ret = z_erofs_read_one_data(inode, &map, raw, buffer,
						    0, map.m_llen, false);
			if (ret)
				goto out;

			if (outfd >= 0 && write(outfd, buffer, map.m_llen) < 0)
				goto fail_eio;
		} else {
			u64 p = 0;

			do {
				u64 count = min_t(u64, alloc_rawsize,
						  map.m_llen);

				ret = erofs_read_one_data(inode, &map, raw, p, count);
				if (ret)
					goto out;

				if (outfd >= 0 && write(outfd, raw, count) < 0)
					goto fail_eio;
				map.m_llen -= count;
				p += count;
			} while (map.m_llen);
		}
	}

	if (fsckcfg.print_comp_ratio) {
		if (!erofs_is_packed_inode(inode))
			fsckcfg.logical_blocks += BLK_ROUND_UP(inode->sbi, inode->i_size);
		fsckcfg.physical_blocks += BLK_ROUND_UP(inode->sbi, pchunk_len);
	}
out:
	if (raw)
		free(raw);
	if (buffer)
		free(buffer);
	return ret < 0 ? ret : 0;

fail_eio:
	erofs_err("I/O error occurred when verifying data chunk @ nid %llu",
		  inode->nid | 0ULL);
	ret = -EIO;
	goto out;
}

static inline int erofs_extract_dir(struct erofs_inode *inode)
{
	int ret;

	erofs_dbg("create directory %s", fsckcfg.extract_path);

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, -1);
	if (ret)
		return ret;

	/*
	 * Make directory with default user rwx permissions rather than
	 * the permissions from the filesystem, as these may not have
	 * write/execute permission.  These are fixed up later in
	 * erofsfsck_set_attributes().
	 */
	if (mkdir(fsckcfg.extract_path, 0700) < 0) {
		struct stat st;

		if (errno != EEXIST) {
			erofs_err("failed to create directory: %s (%s)",
				  fsckcfg.extract_path, strerror(errno));
			return -errno;
		}

		if (lstat(fsckcfg.extract_path, &st) ||
		    !S_ISDIR(st.st_mode)) {
			erofs_err("path is not a directory: %s",
				  fsckcfg.extract_path);
			return -ENOTDIR;
		}

		/*
		 * Try to change permissions of existing directory so
		 * that we can write to it
		 */
		if (chmod(fsckcfg.extract_path, 0700) < 0) {
			erofs_err("failed to set permissions: %s (%s)",
				  fsckcfg.extract_path, strerror(errno));
			return -errno;
		}
	}
	return 0;
}

static char *erofsfsck_hardlink_find(erofs_nid_t nid)
{
	struct list_head *head =
			&erofsfsck_link_hashtable[nid % NR_HARDLINK_HASHTABLE];
	struct erofsfsck_hardlink_entry *entry;

	list_for_each_entry(entry, head, list)
		if (entry->nid == nid)
			return entry->path;
	return NULL;
}

static int erofsfsck_hardlink_insert(erofs_nid_t nid, const char *path)
{
	struct erofsfsck_hardlink_entry *entry;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return -ENOMEM;

	entry->nid = nid;
	entry->path = strdup(path);
	if (!entry->path) {
		free(entry);
		return -ENOMEM;
	}

	list_add_tail(&entry->list,
		      &erofsfsck_link_hashtable[nid % NR_HARDLINK_HASHTABLE]);
	return 0;
}

static void erofsfsck_hardlink_init(void)
{
	unsigned int i;

	for (i = 0; i < NR_HARDLINK_HASHTABLE; ++i)
		init_list_head(&erofsfsck_link_hashtable[i]);
}

static void erofsfsck_hardlink_exit(void)
{
	struct erofsfsck_hardlink_entry *entry, *n;
	struct list_head *head;
	unsigned int i;

	for (i = 0; i < NR_HARDLINK_HASHTABLE; ++i) {
		head = &erofsfsck_link_hashtable[i];

		list_for_each_entry_safe(entry, n, head, list) {
			if (entry->path)
				free(entry->path);
			free(entry);
		}
	}
}

static inline int erofs_extract_file(struct erofs_inode *inode)
{
	bool tryagain = true;
	int ret, fd;

	erofs_dbg("extract file to path: %s", fsckcfg.extract_path);

again:
	fd = open(fsckcfg.extract_path,
		  O_WRONLY | O_CREAT | O_NOFOLLOW |
			(fsckcfg.overwrite ? O_TRUNC : O_EXCL), 0700);
	if (fd < 0) {
		if (fsckcfg.overwrite && tryagain) {
			if (errno == EISDIR) {
				erofs_warn("try to forcely remove directory %s",
					   fsckcfg.extract_path);
				if (rmdir(fsckcfg.extract_path) < 0) {
					erofs_err("failed to remove: %s (%s)",
						  fsckcfg.extract_path, strerror(errno));
					return -EISDIR;
				}
			} else if (errno == EACCES &&
				   chmod(fsckcfg.extract_path, 0700) < 0) {
				erofs_err("failed to set permissions: %s (%s)",
					  fsckcfg.extract_path, strerror(errno));
				return -errno;
			}
			tryagain = false;
			goto again;
		}
		erofs_err("failed to open: %s (%s)", fsckcfg.extract_path,
			  strerror(errno));
		return -errno;
	}

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, fd);
	close(fd);
	return ret;
}

static inline int erofs_extract_symlink(struct erofs_inode *inode)
{
	struct erofs_vfile vf;
	bool tryagain = true;
	int ret;
	char *buf = NULL;

	erofs_dbg("extract symlink to path: %s", fsckcfg.extract_path);

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, -1);
	if (ret)
		return ret;

	buf = malloc(inode->i_size + 1);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = erofs_iopen(&vf, inode);
	if (ret)
		goto out;

	ret = erofs_pread(&vf, buf, inode->i_size, 0);
	if (ret) {
		erofs_err("I/O error occurred when reading symlink @ nid %llu: %d",
			  inode->nid | 0ULL, ret);
		goto out;
	}

	buf[inode->i_size] = '\0';
again:
	if (symlink(buf, fsckcfg.extract_path) < 0) {
		if (errno == EEXIST && fsckcfg.overwrite && tryagain) {
			erofs_warn("try to forcely remove file %s",
				   fsckcfg.extract_path);
			if (unlink(fsckcfg.extract_path) < 0) {
				erofs_err("failed to remove: %s",
					  fsckcfg.extract_path);
				ret = -errno;
				goto out;
			}
			tryagain = false;
			goto again;
		}
		erofs_err("failed to create symlink: %s",
			  fsckcfg.extract_path);
		ret = -errno;
	}
out:
	if (buf)
		free(buf);
	return ret;
}

static int erofs_extract_special(struct erofs_inode *inode)
{
	bool tryagain = true;
	int ret;

	erofs_dbg("extract special to path: %s", fsckcfg.extract_path);

	/* verify data chunk layout */
	ret = erofs_verify_inode_data(inode, -1);
	if (ret)
		return ret;

again:
	if (mknod(fsckcfg.extract_path, inode->i_mode, inode->u.i_rdev) < 0) {
		if (errno == EEXIST && fsckcfg.overwrite && tryagain) {
			erofs_warn("try to forcely remove file %s",
				   fsckcfg.extract_path);
			if (unlink(fsckcfg.extract_path) < 0) {
				erofs_err("failed to remove: %s",
					  fsckcfg.extract_path);
				return -errno;
			}
			tryagain = false;
			goto again;
		}
		if (errno == EEXIST || fsckcfg.superuser) {
			erofs_err("failed to create special file: %s",
				  fsckcfg.extract_path);
			ret = -errno;
		} else {
			erofs_warn("failed to create special file: %s, skipped",
				   fsckcfg.extract_path);
			ret = -ECANCELED;
		}
	}
	return ret;
}

static int erofsfsck_dirent_iter(struct erofs_dir_context *ctx)
{
	int ret;
	size_t prev_pos, curr_pos;

	if (ctx->dot_dotdot)
		return 0;

	prev_pos = fsckcfg.extract_pos;
	curr_pos = prev_pos;

	if (prev_pos + ctx->de_namelen >= PATH_MAX) {
		erofs_err("unable to fsck since the path is too long (%llu)",
			  (curr_pos + ctx->de_namelen) | 0ULL);
		return -EOPNOTSUPP;
	}

	if (fsckcfg.extract_path) {
		fsckcfg.extract_path[curr_pos++] = '/';
		strncpy(fsckcfg.extract_path + curr_pos, ctx->dname,
			ctx->de_namelen);
		curr_pos += ctx->de_namelen;
		fsckcfg.extract_path[curr_pos] = '\0';
	} else {
		curr_pos += ctx->de_namelen;
	}
	fsckcfg.extract_pos = curr_pos;
	ret = erofsfsck_check_inode(ctx->dir->nid, ctx->de_nid);

	if (fsckcfg.extract_path)
		fsckcfg.extract_path[prev_pos] = '\0';
	fsckcfg.extract_pos = prev_pos;
	return ret;
}

static int erofsfsck_extract_inode(struct erofs_inode *inode)
{
	int ret;
	char *oldpath;

	if (!fsckcfg.extract_path || erofs_is_packed_inode(inode)) {
verify:
		/* verify data chunk layout */
		return erofs_verify_inode_data(inode, -1);
	}

	oldpath = erofsfsck_hardlink_find(inode->nid);
	if (oldpath) {
		if (link(oldpath, fsckcfg.extract_path) == -1) {
			erofs_err("failed to extract hard link: %s (%s)",
				  fsckcfg.extract_path, strerror(errno));
			return -errno;
		}
		return 0;
	}

	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		ret = erofs_extract_dir(inode);
		break;
	case S_IFREG:
		ret = erofs_extract_file(inode);
		break;
	case S_IFLNK:
		ret = erofs_extract_symlink(inode);
		break;
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		ret = erofs_extract_special(inode);
		break;
	default:
		/* TODO */
		goto verify;
	}
	if (ret && ret != -ECANCELED)
		return ret;

	/* record nid and old path for hardlink */
	if (inode->i_nlink > 1 && !S_ISDIR(inode->i_mode))
		ret = erofsfsck_hardlink_insert(inode->nid,
						fsckcfg.extract_path);
	return ret;
}

static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid)
{
	int ret, i;
	struct erofs_inode inode = {.sbi = &g_sbi, .nid = nid};

	erofs_dbg("check inode: nid(%llu)", nid | 0ULL);
	ret = erofs_read_inode_from_disk(&inode);
	if (ret) {
		if (ret == -EIO)
			erofs_err("I/O error occurred when reading nid(%llu)",
				  nid | 0ULL);
		goto out;
	}

	if (!(fsckcfg.check_decomp && fsckcfg.dump_xattrs)) {
		/* verify xattr field */
		ret = erofs_verify_xattr(&inode);
		if (ret)
			goto out;
	}

	ret = erofsfsck_extract_inode(&inode);
	if (ret && ret != -ECANCELED)
		goto out;

	if (fsckcfg.check_decomp && fsckcfg.dump_xattrs) {
		ret = erofsfsck_dump_xattrs(&inode);
		if (ret)
			return ret;
	}

	if (S_ISDIR(inode.i_mode)) {
		struct erofs_dir_context ctx = {
			.flags = EROFS_READDIR_VALID_PNID,
			.pnid = pnid,
			.dir = &inode,
			.cb = erofsfsck_dirent_iter,
		};

		/* XXX: support the deeper cases later */
		if (fsckcfg.dirstack.top >= ARRAY_SIZE(fsckcfg.dirstack.dirs))
			return -ENAMETOOLONG;
		for (i = 0; i < fsckcfg.dirstack.top; ++i)
			if (inode.nid == fsckcfg.dirstack.dirs[i])
				return -ELOOP;
		fsckcfg.dirstack.dirs[fsckcfg.dirstack.top++] = pnid;
		ret = erofs_iterate_dir(&ctx, true);
		--fsckcfg.dirstack.top;
	}

	if (!ret && !erofs_is_packed_inode(&inode))
		erofsfsck_set_attributes(&inode, fsckcfg.extract_path);

	if (ret == -ECANCELED)
		ret = 0;
out:
	if (ret && ret != -EIO)
		fsckcfg.corrupted = true;
	return ret;
}

#ifdef FUZZING
int erofsfsck_fuzz_one(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
	int err;

	erofs_init_configure();

	fsckcfg.physical_blocks = 0;
	fsckcfg.logical_blocks = 0;
	fsckcfg.extract_path = NULL;
	fsckcfg.extract_pos = 0;
	fsckcfg.umask = umask(0);
	fsckcfg.superuser = geteuid() == 0;
	fsckcfg.corrupted = false;
	fsckcfg.print_comp_ratio = false;
	fsckcfg.check_decomp = false;
	fsckcfg.force = false;
	fsckcfg.overwrite = false;
	fsckcfg.preserve_owner = fsckcfg.superuser;
	fsckcfg.preserve_perms = fsckcfg.superuser;
	fsckcfg.dump_xattrs = false;

	err = erofsfsck_parse_options_cfg(argc, argv);
	if (err) {
		if (err == -EINVAL)
			fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		goto exit;
	}

#ifdef FUZZING
	cfg.c_dbg_lvl = -1;
	fsckcfg.nosbcrc = true;
#endif

	err = erofs_dev_open(&g_sbi, cfg.c_img_path, O_RDONLY);
	if (err) {
		erofs_err("failed to open image file");
		goto exit;
	}

	err = erofs_read_superblock(&g_sbi);
	if (err) {
		erofs_err("failed to read superblock");
		goto exit_dev_close;
	}

	if (!fsckcfg.nosbcrc && erofs_sb_has_sb_chksum(&g_sbi) &&
	    erofs_superblock_csum_verify(&g_sbi)) {
		fsckcfg.corrupted = true;
		erofs_err("failed to verify superblock checksum");
		goto exit_put_super;
	}

	if (fsckcfg.extract_path)
		erofsfsck_hardlink_init();

	if (erofs_sb_has_fragments(&g_sbi) && g_sbi.packed_nid > 0) {
		err = erofs_packedfile_init(&g_sbi, false);
		if (err) {
			erofs_err("failed to initialize packedfile: %s",
				  erofs_strerror(err));
			goto exit_hardlink;
		}

		err = erofsfsck_check_inode(g_sbi.packed_nid, g_sbi.packed_nid);
		if (err) {
			erofs_err("failed to verify packed file");
			goto exit_packedinode;
		}
	}

	err = erofsfsck_check_inode(g_sbi.root_nid, g_sbi.root_nid);
	if (fsckcfg.corrupted) {
		if (!fsckcfg.extract_path)
			erofs_err("Found some filesystem corruption");
		else
			erofs_err("Failed to extract filesystem");
		err = -EFSCORRUPTED;
	} else if (!err) {
		if (!fsckcfg.extract_path)
			erofs_info("No errors found");
		else
			erofs_info("Extracted filesystem successfully");

		if (fsckcfg.print_comp_ratio) {
			double comp_ratio =
				(double)fsckcfg.physical_blocks * 100 /
				(double)fsckcfg.logical_blocks;

			erofs_info("Compression ratio: %.2f(%%)", comp_ratio);
		}
	}

exit_packedinode:
	erofs_packedfile_exit(&g_sbi);
exit_hardlink:
	if (fsckcfg.extract_path)
		erofsfsck_hardlink_exit();
exit_put_super:
	erofs_put_super(&g_sbi);
exit_dev_close:
	erofs_dev_close(&g_sbi);
exit:
	erofs_blob_closeall(&g_sbi);
	erofs_exit_configure();
	return err ? 1 : 0;
}

#ifdef FUZZING
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	int fd, ret;
	char filename[] = "/tmp/erofsfsck_libfuzzer_XXXXXX";
	char *argv[] = {
		"fsck.erofs",
		"--extract",
		filename,
	};

	fd = mkstemp(filename);
	if (fd < 0)
		return -errno;
	if (write(fd, Data, Size) != Size) {
		close(fd);
		return -EIO;
	}
	close(fd);
	ret = erofsfsck_fuzz_one(ARRAY_SIZE(argv), argv);
	unlink(filename);
	return ret ? -1 : 0;
}
#endif
