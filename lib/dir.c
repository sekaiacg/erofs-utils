// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include <stdlib.h>
#include <sys/stat.h>
#include "erofs/print.h"
#include "erofs/dir.h"

/* filename should not have a '/' in the name string */
static bool erofs_validate_filename(const char *dname, int size)
{
	char *name = (char *)dname;

	while (name - dname < size && *name != '\0') {
		if (*name == '/')
			return false;
		++name;
	}
	return true;
}

static int traverse_dirents(struct erofs_dir_context *ctx,
			    void *dentry_blk, erofs_off_t lblk,
			    unsigned int next_nameoff, unsigned int maxsize,
			    bool fsck)
{
	struct erofs_sb_info *sbi = ctx->dir->sbi;
	struct erofs_dirent *de = dentry_blk;
	const struct erofs_dirent *end = dentry_blk + next_nameoff;
	const char *prev_name = NULL;
	const char *errmsg;
	unsigned int prev_namelen = 0;
	int ret = 0;
	bool silent = false;

	while (de < end) {
		const char *de_name;
		unsigned int de_namelen;
		unsigned int nameoff;

		nameoff = le16_to_cpu(de->nameoff);
		de_name = (char *)dentry_blk + nameoff;

		/* the last dirent check */
		if (de + 1 >= end)
			de_namelen = strnlen(de_name, maxsize - nameoff);
		else
			de_namelen = le16_to_cpu(de[1].nameoff) - nameoff;

		ctx->de_nid = le64_to_cpu(de->nid);
		erofs_dbg("traversed nid (%llu)", ctx->de_nid | 0ULL);

		ret = -EFSCORRUPTED;
		/* corrupted entry check */
		if (nameoff != next_nameoff) {
			errmsg = "bogus dirent nameoff";
			break;
		}

		if (nameoff + de_namelen > maxsize || !de_namelen ||
				de_namelen > EROFS_NAME_LEN) {
			errmsg = "bogus dirent namelen";
			break;
		}

		if (fsck && prev_name) {
			int cmp = strncmp(prev_name, de_name,
					  min(prev_namelen, de_namelen));

			if (cmp > 0 || (cmp == 0 &&
					prev_namelen >= de_namelen)) {
				errmsg = "wrong dirent name order";
				break;
			}
		}

		if (fsck && de->file_type >= EROFS_FT_MAX) {
			errmsg = "invalid file type %u";
			break;
		}

		ctx->dname = de_name;
		ctx->de_namelen = de_namelen;
		ctx->de_ftype = de->file_type;
		ctx->dot_dotdot = is_dot_dotdot_len(de_name, de_namelen);
		if (ctx->dot_dotdot) {
			switch (de_namelen) {
			case 2:
				if (fsck &&
				    (ctx->flags & EROFS_READDIR_DOTDOT_FOUND)) {
					errmsg = "duplicated `..' dirent";
					goto out;
				}
				ctx->flags |= EROFS_READDIR_DOTDOT_FOUND;
				if (sbi->root_nid == ctx->dir->nid) {
					ctx->pnid = sbi->root_nid;
					ctx->flags |= EROFS_READDIR_VALID_PNID;
				}
				if (fsck &&
				    (ctx->flags & EROFS_READDIR_VALID_PNID) &&
				    ctx->de_nid != ctx->pnid) {
					errmsg = "corrupted `..' dirent";
					goto out;
				}
				break;
			case 1:
				if (fsck &&
				    (ctx->flags & EROFS_READDIR_DOT_FOUND)) {
					errmsg = "duplicated `.' dirent";
					goto out;
				}

				ctx->flags |= EROFS_READDIR_DOT_FOUND;
				if (fsck && ctx->de_nid != ctx->dir->nid) {
					errmsg = "corrupted `.' dirent";
					goto out;
				}
				break;
			}
		} else if (fsck &&
			   !erofs_validate_filename(de_name, de_namelen)) {
			errmsg = "corrupted dirent with illegal filename";
			goto out;
		}
		ret = ctx->cb(ctx);
		if (ret) {
			silent = true;
			break;
		}
		prev_name = de_name;
		prev_namelen = de_namelen;
		next_nameoff += de_namelen;
		++de;
	}
out:
	if (ret && !silent)
		erofs_err("%s @ nid %llu, lblk %llu, index %lu",
			  errmsg, ctx->dir->nid | 0ULL, lblk | 0ULL,
			  (de - (struct erofs_dirent *)dentry_blk) | 0UL);
	return ret;
}

int erofs_iterate_dir(struct erofs_dir_context *ctx, bool fsck)
{
	struct erofs_inode *dir = ctx->dir;
	struct erofs_sb_info *sbi = dir->sbi;
	struct erofs_vfile vf;
	erofs_off_t pos;
	char buf[EROFS_MAX_BLOCK_SIZE];
	int err = 0;

	if (!S_ISDIR(dir->i_mode))
		return -ENOTDIR;

	ctx->flags &= ~EROFS_READDIR_ALL_SPECIAL_FOUND;
	if (dir->dot_omitted)
		ctx->flags |= EROFS_READDIR_DOT_FOUND;
	err = erofs_iopen(&vf, dir);
	if (err)
		return err;

	for (pos = 0; pos < dir->i_size; ) {
		erofs_blk_t lblk = erofs_blknr(sbi, pos);
		erofs_off_t maxsize = min_t(erofs_off_t,
					dir->i_size - pos, erofs_blksiz(sbi));
		const struct erofs_dirent *de = (const void *)buf;
		unsigned int nameoff;

		err = erofs_pread(&vf, buf, maxsize, pos);
		if (err) {
			erofs_err("I/O error when reading dirents @ nid %llu, lblk %llu: %s",
				  dir->nid | 0ULL, lblk | 0ULL,
				  erofs_strerror(err));
			return err;
		}

		nameoff = le16_to_cpu(de->nameoff);
		if (nameoff < sizeof(struct erofs_dirent) ||
		    nameoff >= erofs_blksiz(sbi)) {
			erofs_err("invalid de[0].nameoff %u @ nid %llu, lblk %llu",
				  nameoff, dir->nid | 0ULL, lblk | 0ULL);
			return -EFSCORRUPTED;
		}
		err = traverse_dirents(ctx, buf, lblk, nameoff, maxsize, fsck);
		if (err)
			break;
		pos += maxsize;
	}

	if (fsck && (ctx->flags & EROFS_READDIR_ALL_SPECIAL_FOUND) !=
			EROFS_READDIR_ALL_SPECIAL_FOUND && !err) {
		erofs_err("`.' or `..' dirent is missing @ nid %llu",
			  dir->nid | 0ULL);
		return -EFSCORRUPTED;
	}
	return err;
}

#define EROFS_PATHNAME_FOUND 1

struct erofs_get_pathname_context {
	struct erofs_dir_context ctx;
	erofs_nid_t target_nid;
	char *buf;
	size_t size;
	size_t pos;
};

static int erofs_get_pathname_iter(struct erofs_dir_context *ctx)
{
	int ret;
	struct erofs_get_pathname_context *pathctx = (void *)ctx;
	const char *dname = ctx->dname;
	size_t len = ctx->de_namelen;
	size_t pos = pathctx->pos;

	if (ctx->dot_dotdot)
		return 0;

	if (ctx->de_nid == pathctx->target_nid) {
		if (pos + len + 2 > pathctx->size) {
			erofs_err("get_pathname buffer not large enough: len %zd, size %zd",
				  pos + len + 2, pathctx->size);
			return -ERANGE;
		}

		pathctx->buf[pos++] = '/';
		strncpy(pathctx->buf + pos, dname, len);
		pathctx->buf[pos + len] = '\0';
		return EROFS_PATHNAME_FOUND;
	}

	if (ctx->de_ftype == EROFS_FT_DIR || ctx->de_ftype == EROFS_FT_UNKNOWN) {
		struct erofs_inode dir = {
			.sbi = ctx->dir->sbi,
			.nid = ctx->de_nid
		};

		ret = erofs_read_inode_from_disk(&dir);
		if (ret) {
			erofs_err("read inode failed @ nid %llu", dir.nid | 0ULL);
			return ret;
		}

		if (S_ISDIR(dir.i_mode)) {
			struct erofs_get_pathname_context nctx = {
				.ctx.flags = 0,
				.ctx.dir = &dir,
				.ctx.cb = erofs_get_pathname_iter,
				.target_nid = pathctx->target_nid,
				.buf = pathctx->buf,
				.size = pathctx->size,
				.pos = pos + len + 1,
			};
			ret = erofs_iterate_dir(&nctx.ctx, false);
			if (ret == EROFS_PATHNAME_FOUND) {
				pathctx->buf[pos++] = '/';
				strncpy(pathctx->buf + pos, dname, len);
			}
			return ret;
		} else if (ctx->de_ftype == EROFS_FT_DIR) {
			erofs_err("i_mode and file_type are inconsistent @ nid %llu",
				  dir.nid | 0ULL);
		}
	}
	return 0;
}

int erofs_get_pathname(struct erofs_sb_info *sbi, erofs_nid_t nid,
		       char *buf, size_t size)
{
	int ret;
	struct erofs_inode root = {
		.sbi = sbi,
		.nid = sbi->root_nid,
	};
	struct erofs_get_pathname_context pathctx = {
		.ctx.flags = 0,
		.ctx.dir = &root,
		.ctx.cb = erofs_get_pathname_iter,
		.target_nid = nid,
		.buf = buf,
		.size = size,
		.pos = 0,
	};

	if (nid == root.nid) {
		if (size < 2) {
			erofs_err("get_pathname buffer not large enough: len 2, size %zd",
				  size);
			return -ERANGE;
		}

		buf[0] = '/';
		buf[1] = '\0';
		return 0;
	}

	ret = erofs_read_inode_from_disk(&root);
	if (ret) {
		erofs_err("read inode failed @ nid %llu", root.nid | 0ULL);
		return ret;
	}

	ret = erofs_iterate_dir(&pathctx.ctx, false);
	if (ret == EROFS_PATHNAME_FOUND)
		return 0;
	if (!ret)
		return -ENOENT;
	return ret;
}
