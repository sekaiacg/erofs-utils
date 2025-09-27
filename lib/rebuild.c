// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <config.h>
#if defined(HAVE_SYS_SYSMACROS_H)
#include <sys/sysmacros.h>
#endif
#include "erofs/print.h"
#include "erofs/inode.h"
#include "erofs/rebuild.h"
#include "erofs/dir.h"
#include "erofs/xattr.h"
#include "erofs/blobchunk.h"
#include "erofs/internal.h"
#include "liberofs_uuid.h"

#ifdef HAVE_LINUX_AUFS_TYPE_H
#include <linux/aufs_type.h>
#else
#define AUFS_WH_PFX		".wh."
#define AUFS_DIROPQ_NAME	AUFS_WH_PFX ".opq"
#define AUFS_WH_DIROPQ		AUFS_WH_PFX AUFS_DIROPQ_NAME
#endif

/*
 * These non-existent parent directories are created with the same permissions
 * as their parent directories.  It is expected that a call to create these
 * parent directories with the correct permissions will be made later, at which
 * point the permissions will be updated.  We handle mtime in the same way.
 * Also see: https://github.com/containerd/containerd/issues/3017
 *           https://github.com/containerd/containerd/pull/3528
 */
static struct erofs_dentry *erofs_rebuild_mkdir(struct erofs_inode *dir,
						const char *s)
{
	struct erofs_inode *inode;
	struct erofs_dentry *d;

	inode = erofs_new_inode(dir->sbi);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	if (asprintf(&inode->i_srcpath, "%s/%s",
		     dir->i_srcpath ? : "", s) < 0) {
		erofs_iput(inode);
		return ERR_PTR(-ENOMEM);
	}
	inode->i_mode = S_IFDIR | 0755;
	if (dir->i_mode & S_IWGRP)
		inode->i_mode |= S_IWGRP;
	if (dir->i_mode & S_IWOTH)
		inode->i_mode |= S_IWOTH;
	inode->i_parent = dir;
	inode->i_uid = dir->i_uid;
	inode->i_gid = dir->i_gid;
	inode->i_mtime = dir->i_mtime;
	inode->i_mtime_nsec = dir->i_mtime_nsec;
	inode->dev = dir->dev;
	inode->i_nlink = 2;

	d = erofs_d_alloc(dir, s);
	if (IS_ERR(d)) {
		erofs_iput(inode);
	} else {
		d->type = EROFS_FT_DIR;
		d->inode = inode;
	}
	return d;
}

struct erofs_dentry *erofs_d_lookup(struct erofs_inode *dir, const char *name)
{
	struct erofs_dentry *d;

	list_for_each_entry(d, &dir->i_subdirs, d_child)
		if (!strcmp(d->name, name))
			return d;
	return NULL;
}

struct erofs_dentry *erofs_rebuild_get_dentry(struct erofs_inode *pwd,
		char *path, bool aufs, bool *whout, bool *opq, bool to_head)
{
	struct erofs_dentry *d = NULL;
	char *s = path;

	*whout = false;
	*opq = false;

	while (1) {
		char *slash = strchr(s, '/');

		if (slash) {
			if (s == slash) {
				while (*++s == '/');	/* skip '//...' */
				continue;
			}
			*slash = '\0';
		} else if (*s == '\0') {
			break;
		}

		if (__erofs_unlikely(is_dot_dotdot(s))) {
			if (s[1] == '.') {
				pwd = pwd->i_parent;
			}
		} else {
			if (aufs && !slash) {
				if (!strcmp(s, AUFS_WH_DIROPQ)) {
					*opq = true;
					break;
				}
				if (!strncmp(s, AUFS_WH_PFX, sizeof(AUFS_WH_PFX) - 1)) {
					s += sizeof(AUFS_WH_PFX) - 1;
					*whout = true;
				}
			}

			d = erofs_d_lookup(pwd, s);
			if (d) {
				if (d->type != EROFS_FT_DIR) {
					if (slash)
						return ERR_PTR(-ENOTDIR);
				} else if (to_head) {
					list_del(&d->d_child);
					list_add(&d->d_child, &pwd->i_subdirs);
				}
				pwd = d->inode;
			} else if (slash) {
				d = erofs_rebuild_mkdir(pwd, s);
				if (IS_ERR(d))
					return d;
			} else {
				d = erofs_d_alloc(pwd, s);
				if (IS_ERR(d))
					return d;
				d->type = EROFS_FT_UNKNOWN;
				d->inode = pwd;
			}
			pwd = d->inode;
		}

		if (!slash)
			break;
		*slash = '/';
		s = slash + 1;
	}
	return d;
}

static int erofs_rebuild_write_blob_index(struct erofs_sb_info *dst_sb,
					  struct erofs_inode *inode)
{
	int ret;
	unsigned int count, unit, chunkbits, i;
	struct erofs_inode_chunk_index *idx;
	erofs_off_t chunksize;
	erofs_blk_t blkaddr;

	/* TODO: fill data map in other layouts */
	if (inode->datalayout == EROFS_INODE_CHUNK_BASED) {
		chunkbits = inode->u.chunkbits;
		if (chunkbits < dst_sb->blkszbits) {
			erofs_err("%s: chunk size %u is smaller than the target block size %u",
				  inode->i_srcpath, 1U << chunkbits,
				  1U << dst_sb->blkszbits);
			return -EINVAL;
		}
	} else if (inode->datalayout == EROFS_INODE_FLAT_PLAIN) {
		chunkbits = ilog2(inode->i_size - 1) + 1;
		if (chunkbits < dst_sb->blkszbits)
			chunkbits = dst_sb->blkszbits;
		if (chunkbits - dst_sb->blkszbits > EROFS_CHUNK_FORMAT_BLKBITS_MASK)
			chunkbits = EROFS_CHUNK_FORMAT_BLKBITS_MASK + dst_sb->blkszbits;
	} else {
		erofs_err("%s: unsupported datalayout %d ", inode->i_srcpath,
			  inode->datalayout);
		return -EOPNOTSUPP;
	}

	chunksize = 1ULL << chunkbits;
	count = DIV_ROUND_UP(inode->i_size, chunksize);

	unit = sizeof(struct erofs_inode_chunk_index);
	inode->extent_isize = count * unit;
	idx = calloc(count, max(sizeof(*idx), sizeof(void *)));
	if (!idx)
		return -ENOMEM;
	inode->chunkindexes = idx;

	for (i = 0; i < count; i++) {
		struct erofs_blobchunk *chunk;
		struct erofs_map_blocks map = {
			.buf = __EROFS_BUF_INITIALIZER,
		};

		map.m_la = i << chunkbits;
		ret = erofs_map_blocks(inode, &map, 0);
		if (ret)
			goto err;

		blkaddr = erofs_blknr(dst_sb, map.m_pa);
		chunk = erofs_get_unhashed_chunk(inode->dev, blkaddr, 0);
		if (IS_ERR(chunk)) {
			ret = PTR_ERR(chunk);
			goto err;
		}
		*(void **)idx++ = chunk;

	}
	inode->datalayout = EROFS_INODE_CHUNK_BASED;
	inode->u.chunkformat = EROFS_CHUNK_FORMAT_INDEXES;
	inode->u.chunkformat |= chunkbits - dst_sb->blkszbits;
	return 0;
err:
	free(inode->chunkindexes);
	inode->chunkindexes = NULL;
	return ret;
}

static int erofs_rebuild_update_inode(struct erofs_sb_info *dst_sb,
				      struct erofs_inode *inode,
				      enum erofs_rebuild_datamode datamode)
{
	int err = 0;

	switch (inode->i_mode & S_IFMT) {
	case S_IFCHR:
		if (erofs_inode_is_whiteout(inode))
			inode->i_parent->whiteouts = true;
		__erofs_fallthrough;
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		inode->i_size = 0;
		erofs_dbg("\tdev: %d %d", major(inode->u.i_rdev),
			  minor(inode->u.i_rdev));
		inode->u.i_rdev = erofs_new_encode_dev(inode->u.i_rdev);
		break;
	case S_IFDIR:
		inode->i_nlink = 2;
		break;
	case S_IFLNK: {
		struct erofs_vfile vf;

		inode->i_link = malloc(inode->i_size + 1);
		if (!inode->i_link)
			return -ENOMEM;
		err = erofs_iopen(&vf, inode);
		if (err)
			return err;
		err = erofs_pread(&vf, inode->i_link, inode->i_size, 0);
		erofs_dbg("\tsymlink: %s -> %s", inode->i_srcpath, inode->i_link);
		break;
	}
	case S_IFREG:
		if (!inode->i_size) {
			inode->u.i_blkaddr = EROFS_NULL_ADDR;
			break;
		}
		if (datamode == EROFS_REBUILD_DATA_BLOB_INDEX)
			err = erofs_rebuild_write_blob_index(dst_sb, inode);
		else if (datamode == EROFS_REBUILD_DATA_RESVSP)
			inode->datasource = EROFS_INODE_DATA_SOURCE_RESVSP;
		else
			err = -EOPNOTSUPP;
		break;
	default:
		return -EINVAL;
	}
	return err;
}

/*
 * @mergedir: parent directory in the merged tree
 * @ctx.dir:  parent directory when itering erofs_iterate_dir()
 * @datamode: indicate how to import inode data
 */
struct erofs_rebuild_dir_context {
	struct erofs_dir_context ctx;
	struct erofs_inode *mergedir;
	enum erofs_rebuild_datamode datamode;
};

static int erofs_rebuild_dirent_iter(struct erofs_dir_context *ctx)
{
	struct erofs_rebuild_dir_context *rctx = (void *)ctx;
	struct erofs_inode *mergedir = rctx->mergedir;
	struct erofs_inode *dir = ctx->dir;
	struct erofs_inode *inode, *candidate;
	struct erofs_inode src;
	struct erofs_dentry *d;
	char *path, *dname;
	bool dumb;
	int ret;

	if (ctx->dot_dotdot)
		return 0;

	ret = asprintf(&path, "%s/%.*s", rctx->mergedir->i_srcpath,
		       ctx->de_namelen, ctx->dname);
	if (ret < 0)
		return ret;

	erofs_dbg("parsing %s", path);
	dname = path + strlen(mergedir->i_srcpath) + 1;

	d = erofs_rebuild_get_dentry(mergedir, dname, false,
				     &dumb, &dumb, false);
	if (IS_ERR(d)) {
		ret = PTR_ERR(d);
		goto out;
	}

	ret = 0;
	if (d->type != EROFS_FT_UNKNOWN) {
		/*
		 * bail out if the file exists in the upper layers.  (Note that
		 * extended attributes won't be merged too even for dirs.)
		 */
		if (!S_ISDIR(d->inode->i_mode) || d->inode->opaque)
			goto out;

		/* merge directory entries */
		src = (struct erofs_inode) {
			.sbi = dir->sbi,
			.nid = ctx->de_nid
		};
		ret = erofs_read_inode_from_disk(&src);
		if (ret || !S_ISDIR(src.i_mode))
			goto out;
		mergedir = d->inode;
		inode = dir = &src;
	} else {
		u64 nid;

		DBG_BUGON(mergedir != d->inode);
		inode = erofs_new_inode(dir->sbi);
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			goto out;
		}

		/* reuse i_ino[0] to read nid in source fs */
		nid = inode->i_ino[0];
		inode->sbi = dir->sbi;
		inode->nid = ctx->de_nid;
		ret = erofs_read_inode_from_disk(inode);
		if (ret)
			goto out;

		/* restore nid in new generated fs */
		inode->i_ino[1] = inode->i_ino[0];
		inode->i_ino[0] = nid;
		inode->dev = inode->sbi->dev;

		if (S_ISREG(inode->i_mode) && inode->i_nlink > 1 &&
		    (candidate = erofs_iget(inode->dev, ctx->de_nid))) {
			/* hardlink file */
			erofs_iput(inode);
			inode = candidate;
			if (S_ISDIR(inode->i_mode)) {
				erofs_err("hardlink directory not supported");
				ret = -EISDIR;
				goto out;
			}
			inode->i_nlink++;
			erofs_dbg("\thardlink: %s -> %s", path, inode->i_srcpath);
		} else {
			ret = erofs_read_xattrs_from_disk(inode);
			if (ret) {
				erofs_iput(inode);
				goto out;
			}

			inode->i_parent = d->inode;
			inode->i_srcpath = path;
			path = NULL;
			inode->i_ino[1] = inode->nid;
			inode->i_nlink = 1;

			ret = erofs_rebuild_update_inode(&g_sbi, inode,
							 rctx->datamode);
			if (ret) {
				erofs_iput(inode);
				goto out;
			}

			erofs_insert_ihash(inode);
			mergedir = dir = inode;
		}

		d->inode = inode;
		d->type = erofs_mode_to_ftype(inode->i_mode);
	}

	if (S_ISDIR(inode->i_mode)) {
		struct erofs_rebuild_dir_context nctx = *rctx;

		nctx.mergedir = mergedir;
		nctx.ctx.dir = dir;
		ret = erofs_iterate_dir(&nctx.ctx, false);
		if (ret)
			goto out;
	}

	/* reset sbi, nid after subdirs are all loaded for the final dump */
	inode->sbi = &g_sbi;
	inode->nid = EROFS_NID_UNALLOCATED;
out:
	free(path);
	return ret;
}

int erofs_rebuild_load_tree(struct erofs_inode *root, struct erofs_sb_info *sbi,
			    enum erofs_rebuild_datamode mode)
{
	struct erofs_inode inode = {};
	struct erofs_rebuild_dir_context ctx;
	char uuid_str[37];
	char *fsid = sbi->devname;
	int ret;

	if (!fsid) {
		erofs_uuid_unparse_lower(sbi->uuid, uuid_str);
		fsid = uuid_str;
	}

	ret = erofs_read_superblock(sbi);
	if (ret) {
		erofs_err("failed to read superblock of %s", fsid);
		return ret;
	}

	inode.nid = sbi->root_nid;
	inode.sbi = sbi;
	ret = erofs_read_inode_from_disk(&inode);
	if (ret) {
		erofs_err("failed to read root inode of %s", fsid);
		return ret;
	}
	inode.i_srcpath = strdup("/");

	ctx = (struct erofs_rebuild_dir_context) {
		.ctx.dir = &inode,
		.ctx.cb = erofs_rebuild_dirent_iter,
		.mergedir = root,
		.datamode = mode,
	};
	ret = erofs_iterate_dir(&ctx.ctx, false);
	free(inode.i_srcpath);
	return ret;
}

static int erofs_rebuild_basedir_dirent_iter(struct erofs_dir_context *ctx)
{
	struct erofs_rebuild_dir_context *rctx = (void *)ctx;
	struct erofs_inode *dir = ctx->dir;
	struct erofs_inode *mergedir = rctx->mergedir;
	struct erofs_dentry *d;
	char *dname;
	bool dumb;
	int ret;

	if (ctx->dot_dotdot)
		return 0;

	dname = strndup(ctx->dname, ctx->de_namelen);
	if (!dname)
		return -ENOMEM;
	d = erofs_rebuild_get_dentry(mergedir, dname, false,
				     &dumb, &dumb, false);
	if (IS_ERR(d)) {
		ret = PTR_ERR(d);
		goto out;
	}

	if (d->type == EROFS_FT_UNKNOWN) {
		d->nid = ctx->de_nid;
		d->type = ctx->de_ftype;
		d->validnid = true;
		if (!mergedir->whiteouts && erofs_dentry_is_wht(dir->sbi, d))
			mergedir->whiteouts = true;
	} else if (__erofs_unlikely(d->validnid)) {
		/* The base image appears to be corrupted */
		DBG_BUGON(1);
		ret = -EFSCORRUPTED;
		goto out;
	} else {
		struct erofs_inode *inode = d->inode;

		/* update sub-directories only for recursively loading */
		if (S_ISDIR(inode->i_mode) &&
		    (ctx->de_ftype == EROFS_FT_DIR ||
		     ctx->de_ftype == EROFS_FT_UNKNOWN)) {
			erofs_remove_ihash(inode);
			inode->dev = dir->sbi->dev;
			inode->i_ino[1] = ctx->de_nid;
			erofs_insert_ihash(inode);
		}
	}
	ret = 0;
out:
	free(dname);
	return ret;
}

int erofs_rebuild_load_basedir(struct erofs_inode *dir)
{
	struct erofs_inode fakeinode = {
		.sbi = dir->sbi,
		.nid = dir->i_ino[1],
	};
	struct erofs_rebuild_dir_context ctx;
	int ret;

	ret = erofs_read_inode_from_disk(&fakeinode);
	if (ret) {
		erofs_err("failed to read inode @ %llu", fakeinode.nid);
		return ret;
	}

	/* Inherit the maximum xattr size for the root directory */
	if (__erofs_unlikely(IS_ROOT(dir)))
		dir->xattr_isize = fakeinode.xattr_isize;

	/*
	 * May be triggered if ftype == EROFS_FT_UNKNOWN, which is impossible
	 * with the current mkfs.
	 */
	if (__erofs_unlikely(!S_ISDIR(fakeinode.i_mode))) {
		DBG_BUGON(1);
		return 0;
	}

	ctx = (struct erofs_rebuild_dir_context) {
		.ctx.dir = &fakeinode,
		.ctx.cb = erofs_rebuild_basedir_dirent_iter,
		.mergedir = dir,
	};
	return erofs_iterate_dir(&ctx.ctx, false);
}
