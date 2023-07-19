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
#include "erofs/print.h"
#include "erofs/io.h"
#include "erofs/compress.h"
#include "erofs/decompress.h"
#include "erofs/dir.h"

static int erofsfsck_check_inode(erofs_nid_t pnid, erofs_nid_t nid);

struct erofsfsck_cfg {
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
};
static struct erofsfsck_cfg fsckcfg;

static struct option long_options[] = {
	{"help", no_argument, 0, 1},
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
	unsigned int i = 0;
	const char *s;

	while ((s = z_erofs_list_available_compressors(i)) != NULL) {
		if (i++)
			fputs(delim, f);
		fputs(s, f);
	}
	fputc('\n', f);
}

static void usage(void)
{
	fputs("usage: [options] IMAGE\n\n"
	      "Check erofs filesystem compatibility and integrity of IMAGE, and [options] are:\n"
	      " -V                     print the version number of fsck.erofs and exit\n"
	      " -d#                    set output message level to # (maximum 9)\n"
	      " -p                     print total compression ratio of all files\n"
	      " --device=X             specify an extra device to be used together\n"
	      " --extract[=X]          check if all files are well encoded, optionally extract to X\n"
	      " --help                 display this help and exit\n"
	      "\nExtraction options (--extract=X is required):\n"
	      " --force                allow extracting to root\n"
	      " --overwrite            overwrite files that already exist\n"
	      " --preserve             extract with the same ownership and permissions as on the filesystem\n"
	      "                        (default for superuser)\n"
	      " --preserve-owner       extract with the same ownership as on the filesystem\n"
	      " --preserve-perms       extract with the same permissions as on the filesystem\n"
	      " --no-preserve          extract as yourself and apply user's umask on permissions\n"
	      "                        (default for ordinary users)\n"
	      " --no-preserve-owner    extract as yourself\n"
	      " --no-preserve-perms    apply user's umask when extracting permissions\n"
	      "\nSupported algorithms are: ", stderr);
	print_available_decompressors(stderr, ", ");
}

static void erofsfsck_print_version(void)
{
	printf("fsck.erofs %s\n", cfg.c_version);
}

static int erofsfsck_parse_options_cfg(int argc, char **argv)
{
	int opt, ret;
	bool has_opt_preserve = false;

	while ((opt = getopt_long(argc, argv, "Vd:p",
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
		case 1:
			usage();
			exit(0);
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
			ret = blob_open_ro(optarg);
			if (ret)
				return ret;
			++sbi.extra_devices;
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

	if (!S_ISLNK(inode->i_mode)) {
		if (fsckcfg.preserve_perms)
			ret = chmod(path, inode->i_mode);
		else
			ret = chmod(path, inode->i_mode & ~fsckcfg.umask);
		if (ret < 0)
			erofs_warn("failed to set permissions: %s", path);
	}

	if (fsckcfg.preserve_owner) {
		ret = lchown(path, inode->i_uid, inode->i_gid);
		if (ret < 0)
			erofs_warn("failed to change ownership: %s", path);
	}
}

static int erofs_check_sb_chksum(void)
{
#ifndef FUZZING
	u8 buf[EROFS_MAX_BLOCK_SIZE];
	u32 crc;
	struct erofs_super_block *sb;
	int ret;

	ret = blk_read(0, buf, 0, 1);
	if (ret) {
		erofs_err("failed to read superblock to check checksum: %d",
			  ret);
		return -1;
	}

	sb = (struct erofs_super_block *)(buf + EROFS_SUPER_OFFSET);
	sb->checksum = 0;

	crc = erofs_crc32c(~0, (u8 *)sb, erofs_blksiz() - EROFS_SUPER_OFFSET);
	if (crc != sbi.checksum) {
		erofs_err("superblock chksum doesn't match: saved(%08xh) calculated(%08xh)",
			  sbi.checksum, crc);
		fsckcfg.corrupted = true;
		return -1;
	}
#endif
	return 0;
}

static int erofs_verify_xattr(struct erofs_inode *inode)
{
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
	ret = dev_read(0, buf, addr, xattr_hdr_size);
	if (ret < 0) {
		erofs_err("failed to read xattr header @ nid %llu: %d",
			  inode->nid | 0ULL, ret);
		goto out;
	}
	ih = (struct erofs_xattr_ibody_header *)buf;
	xattr_shared_count = ih->h_shared_count;

	ofs = erofs_blkoff(addr) + xattr_hdr_size;
	addr += xattr_hdr_size;
	remaining -= xattr_hdr_size;
	for (i = 0; i < xattr_shared_count; ++i) {
		if (ofs >= erofs_blksiz()) {
			if (ofs != erofs_blksiz()) {
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

		ret = dev_read(0, buf, addr, xattr_entry_size);
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

static int erofs_verify_inode_data(struct erofs_inode *inode, int outfd)
{
	struct erofs_map_blocks map = {
		.index = UINT_MAX,
	};
	int ret = 0;
	bool compressed;
	erofs_off_t pos = 0;
	u64 pchunk_len = 0;
	unsigned int raw_size = 0, buffer_size = 0;
	char *raw = NULL, *buffer = NULL;

	erofs_dbg("verify data chunk of nid(%llu): type(%d)",
		  inode->nid | 0ULL, inode->datalayout);

	switch (inode->datalayout) {
	case EROFS_INODE_FLAT_PLAIN:
	case EROFS_INODE_FLAT_INLINE:
	case EROFS_INODE_CHUNK_BASED:
		compressed = false;
		break;
	case EROFS_INODE_COMPRESSED_FULL:
	case EROFS_INODE_COMPRESSED_COMPACT:
		compressed = true;
		break;
	default:
		erofs_err("unknown datalayout");
		return -EINVAL;
	}

	while (pos < inode->i_size) {
		unsigned int alloc_rawsize;

		map.m_la = pos;
		if (compressed)
			ret = z_erofs_map_blocks_iter(inode, &map,
					EROFS_GET_BLOCKS_FIEMAP);
		else
			ret = erofs_map_blocks(inode, &map,
					EROFS_GET_BLOCKS_FIEMAP);
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
		if (!(map.m_flags & EROFS_MAP_MAPPED) || !fsckcfg.check_decomp)
			continue;

		if (map.m_plen > Z_EROFS_PCLUSTER_MAX_SIZE) {
			if (compressed) {
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
				buffer_size = map.m_llen;
				buffer = realloc(buffer, buffer_size);
				BUG_ON(!buffer);
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

				ret = erofs_read_one_data(&map, raw, p, count);
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
			fsckcfg.logical_blocks += BLK_ROUND_UP(inode->i_size);
		fsckcfg.physical_blocks += BLK_ROUND_UP(pchunk_len);
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
	if (!entry->path)
		return -ENOMEM;

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
	if (ret)
		return ret;

	if (close(fd))
		return -errno;
	return ret;
}

static inline int erofs_extract_symlink(struct erofs_inode *inode)
{
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

	ret = erofs_pread(inode, buf, inode->i_size, 0);
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
		erofs_err("unable to fsck since the path is too long (%u)",
			  curr_pos + ctx->de_namelen);
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

	if (!fsckcfg.extract_path) {
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
		if (erofs_is_packed_inode(inode))
			goto verify;
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
	int ret;
	struct erofs_inode inode;

	erofs_dbg("check inode: nid(%llu)", nid | 0ULL);

	inode.nid = nid;
	ret = erofs_read_inode_from_disk(&inode);
	if (ret) {
		if (ret == -EIO)
			erofs_err("I/O error occurred when reading nid(%llu)",
				  nid | 0ULL);
		goto out;
	}

	/* verify xattr field */
	ret = erofs_verify_xattr(&inode);
	if (ret)
		goto out;

	ret = erofsfsck_extract_inode(&inode);
	if (ret && ret != -ECANCELED)
		goto out;

	/* XXXX: the dir depth should be restricted in order to avoid loops */
	if (S_ISDIR(inode.i_mode)) {
		struct erofs_dir_context ctx = {
			.flags = EROFS_READDIR_VALID_PNID,
			.pnid = pnid,
			.dir = &inode,
			.cb = erofsfsck_dirent_iter,
		};

		ret = erofs_iterate_dir(&ctx, true);
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

	err = erofsfsck_parse_options_cfg(argc, argv);
	if (err) {
		if (err == -EINVAL)
			usage();
		goto exit;
	}

#ifdef FUZZING
	cfg.c_dbg_lvl = -1;
#endif

	err = dev_open_ro(cfg.c_img_path);
	if (err) {
		erofs_err("failed to open image file");
		goto exit;
	}

	err = erofs_read_superblock();
	if (err) {
		erofs_err("failed to read superblock");
		goto exit_dev_close;
	}

	if (erofs_sb_has_sb_chksum() && erofs_check_sb_chksum()) {
		erofs_err("failed to verify superblock checksum");
		goto exit_put_super;
	}

	if (fsckcfg.extract_path)
		erofsfsck_hardlink_init();

	if (erofs_sb_has_fragments() && sbi.packed_nid > 0) {
		err = erofsfsck_check_inode(sbi.packed_nid, sbi.packed_nid);
		if (err) {
			erofs_err("failed to verify packed file");
			goto exit_hardlink;
		}
	}

	err = erofsfsck_check_inode(sbi.root_nid, sbi.root_nid);
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

exit_hardlink:
	if (fsckcfg.extract_path)
		erofsfsck_hardlink_exit();
exit_put_super:
	erofs_put_super();
exit_dev_close:
	dev_close();
exit:
	blob_closeall();
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
