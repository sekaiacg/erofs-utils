// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Created by Li Guifu <blucerlee@gmail.com>
 */
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <config.h>
#if defined(HAVE_SYS_SYSMACROS_H)
#include <sys/sysmacros.h>
#endif
#include "erofs/print.h"
#include "erofs/internal.h"

static dev_t erofs_new_decode_dev(u32 dev)
{
	const unsigned int major = (dev & 0xfff00) >> 8;
	const unsigned int minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);

	return makedev(major, minor);
}

int erofs_read_inode_from_disk(struct erofs_inode *vi)
{
	struct erofs_sb_info *sbi = vi->sbi;
	erofs_blk_t blkaddr = erofs_blknr(sbi, erofs_iloc(vi));
	unsigned int ofs = erofs_blkoff(sbi, erofs_iloc(vi));
	bool in_mbox = erofs_inode_in_metabox(vi);
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	erofs_blk_t addrmask = BIT_ULL(48) - 1;
	struct erofs_inode_extended *die, copied;
	struct erofs_inode_compact *dic;
	unsigned int ifmt;
	void *ptr;
	int err = 0;

	ptr = erofs_read_metabuf(&buf, sbi, erofs_pos(sbi, blkaddr), in_mbox);
	if (IS_ERR(ptr)) {
		err = PTR_ERR(ptr);
		erofs_err("failed to get inode (nid: %llu) page, err %d",
			  vi->nid, err);
		goto err_out;
	}

	dic = ptr + ofs;
	ifmt = le16_to_cpu(dic->i_format);
	if (ifmt & ~EROFS_I_ALL) {
		erofs_err("unsupported i_format %u of nid %llu",
			  ifmt, vi->nid);
		err = -EOPNOTSUPP;
		goto err_out;
	}

	vi->datalayout = erofs_inode_datalayout(ifmt);
	if (vi->datalayout >= EROFS_INODE_DATALAYOUT_MAX) {
		erofs_err("unsupported datalayout %u of nid %llu",
			  vi->datalayout, vi->nid | 0ULL);
		err = -EOPNOTSUPP;
		goto err_out;
	}

	switch (erofs_inode_version(ifmt)) {
	case EROFS_INODE_LAYOUT_EXTENDED:
		vi->inode_isize = sizeof(struct erofs_inode_extended);
		/* check if the extended inode acrosses block boundary */
		if (ofs + vi->inode_isize <= erofs_blksiz(sbi)) {
			ofs += vi->inode_isize;
			die = (struct erofs_inode_extended *)dic;
			copied.i_u = die->i_u;
			copied.i_nb = die->i_nb;
		} else {
			const unsigned int gotten = erofs_blksiz(sbi) - ofs;

			memcpy(&copied, dic, gotten);
			ptr = erofs_read_metabuf(&buf, sbi,
					erofs_pos(sbi, blkaddr + 1), in_mbox);
			if (IS_ERR(ptr)) {
				err = PTR_ERR(ptr);
				erofs_err("failed to get inode payload block (nid: %llu), err %d",
					  vi->nid, err);
				goto err_out;
			}
			ofs = vi->inode_isize - gotten;
			memcpy((u8 *)&copied + gotten, ptr, ofs);
			die = &copied;
		}
		vi->xattr_isize = erofs_xattr_ibody_size(die->i_xattr_icount);
		vi->i_mode = le16_to_cpu(die->i_mode);
		vi->i_ino[0] = le32_to_cpu(die->i_ino);
		copied.i_u = die->i_u;
		copied.i_nb = die->i_nb;
		vi->i_uid = le32_to_cpu(die->i_uid);
		vi->i_gid = le32_to_cpu(die->i_gid);
		vi->i_nlink = le32_to_cpu(die->i_nlink);

		vi->i_mtime = le64_to_cpu(die->i_mtime);
		vi->i_mtime_nsec = le64_to_cpu(die->i_mtime_nsec);
		vi->i_size = le64_to_cpu(die->i_size);
		break;
	case EROFS_INODE_LAYOUT_COMPACT:
		vi->inode_isize = sizeof(struct erofs_inode_compact);
		ofs += vi->inode_isize;
		vi->xattr_isize = erofs_xattr_ibody_size(dic->i_xattr_icount);
		vi->i_mode = le16_to_cpu(dic->i_mode);
		vi->i_ino[0] = le32_to_cpu(dic->i_ino);
		copied.i_u = dic->i_u;
		copied.i_nb = dic->i_nb;
		vi->i_uid = le16_to_cpu(dic->i_uid);
		vi->i_gid = le16_to_cpu(dic->i_gid);
		if (!S_ISDIR(vi->i_mode) &&
		    ((ifmt >> EROFS_I_NLINK_1_BIT) & 1)) {
			vi->i_nlink = 1;
			copied.i_nb = dic->i_nb;
		} else {
			vi->i_nlink = le16_to_cpu(dic->i_nb.nlink);
			copied.i_nb.startblk_hi = 0;
			addrmask = BIT_ULL(32) - 1;
		}
		vi->i_mtime = sbi->epoch + le32_to_cpu(dic->i_mtime);
		vi->i_mtime_nsec = sbi->fixed_nsec;

		vi->i_size = le32_to_cpu(dic->i_size);
		break;
	default:
		erofs_err("unsupported on-disk inode version %u of nid %llu",
			  erofs_inode_version(ifmt), vi->nid | 0ULL);
		err = -EOPNOTSUPP;
		goto err_out;
	}

	switch (vi->i_mode & S_IFMT) {
	case S_IFDIR:
		vi->dot_omitted = (ifmt >> EROFS_I_DOT_OMITTED_BIT) & 1;
		fallthrough;
	case S_IFREG:
	case S_IFLNK:
		vi->u.i_blkaddr = le32_to_cpu(copied.i_u.startblk_lo) |
			((u64)le16_to_cpu(copied.i_nb.startblk_hi) << 32);
		if (vi->datalayout == EROFS_INODE_FLAT_PLAIN &&
		    !((vi->u.i_blkaddr ^ EROFS_NULL_ADDR) & addrmask))
			vi->u.i_blkaddr = EROFS_NULL_ADDR;
		break;
	case S_IFCHR:
	case S_IFBLK:
		vi->u.i_rdev = erofs_new_decode_dev(le32_to_cpu(copied.i_u.rdev));
		break;
	case S_IFIFO:
	case S_IFSOCK:
		vi->u.i_rdev = 0;
		break;
	default:
		erofs_err("bogus i_mode (%o) @ nid %llu", vi->i_mode,
			  vi->nid | 0ULL);
		err = -EFSCORRUPTED;
		goto err_out;
	}

	vi->flags = 0;
	if (vi->datalayout == EROFS_INODE_CHUNK_BASED) {
		/* fill chunked inode summary info */
		vi->u.chunkformat = le16_to_cpu(copied.i_u.c.format);
		if (vi->u.chunkformat & ~EROFS_CHUNK_FORMAT_ALL) {
			erofs_err("unsupported chunk format %x of nid %llu",
				  vi->u.chunkformat, vi->nid | 0ULL);
			err = -EOPNOTSUPP;
			goto err_out;
		}
		vi->u.chunkbits = sbi->blkszbits +
			(vi->u.chunkformat & EROFS_CHUNK_FORMAT_BLKBITS_MASK);
	}
err_out:
	erofs_put_metabuf(&buf);
	return err;
}

struct erofs_dirent *find_target_dirent(erofs_nid_t pnid,
					void *dentry_blk,
					const char *name, unsigned int len,
					unsigned int nameoff,
					unsigned int maxsize)
{
	struct erofs_dirent *de = dentry_blk;
	const struct erofs_dirent *end = dentry_blk + nameoff;

	while (de < end) {
		const char *de_name;
		unsigned int de_namelen;

		nameoff = le16_to_cpu(de->nameoff);
		de_name = (char *)dentry_blk + nameoff;

		/* the last dirent in the block? */
		if (de + 1 >= end)
			de_namelen = strnlen(de_name, maxsize - nameoff);
		else
			de_namelen = le16_to_cpu(de[1].nameoff) - nameoff;

		/* a corrupted entry is found */
		if (nameoff + de_namelen > maxsize ||
		    de_namelen > EROFS_NAME_LEN) {
			erofs_err("bogus dirent @ nid %llu", pnid | 0ULL);
			DBG_BUGON(1);
			return ERR_PTR(-EFSCORRUPTED);
		}

		if (len == de_namelen && !memcmp(de_name, name, de_namelen))
			return de;
		++de;
	}
	return NULL;
}

struct nameidata {
	struct erofs_sb_info *sbi;
	erofs_nid_t	nid;
	unsigned int	ftype;
};

int erofs_namei(struct nameidata *nd, const char *name, unsigned int len)
{
	erofs_nid_t nid = nd->nid;
	int ret;
	char buf[EROFS_MAX_BLOCK_SIZE];
	struct erofs_sb_info *sbi = nd->sbi;
	struct erofs_inode vi = { .sbi = sbi, .nid = nid };
	struct erofs_vfile vf;
	erofs_off_t offset;

	ret = erofs_read_inode_from_disk(&vi);
	if (ret)
		return ret;

	ret = erofs_iopen(&vf, &vi);
	if (ret)
		return ret;

	offset = 0;
	while (offset < vi.i_size) {
		erofs_off_t maxsize = min_t(erofs_off_t,
					    vi.i_size - offset, erofs_blksiz(sbi));
		struct erofs_dirent *de = (void *)buf;
		unsigned int nameoff;

		ret = erofs_pread(&vf, buf, maxsize, offset);
		if (ret)
			return ret;

		nameoff = le16_to_cpu(de->nameoff);
		if (nameoff < sizeof(struct erofs_dirent) ||
		    nameoff >= erofs_blksiz(sbi)) {
			erofs_err("invalid de[0].nameoff %u @ nid %llu",
				  nameoff, nid | 0ULL);
			return -EFSCORRUPTED;
		}

		de = find_target_dirent(nid, buf, name, len,
					nameoff, maxsize);
		if (IS_ERR(de))
			return PTR_ERR(de);

		if (de) {
			nd->nid = le64_to_cpu(de->nid);
			return 0;
		}
		offset += maxsize;
	}
	return -ENOENT;
}

static int link_path_walk(const char *name, struct nameidata *nd)
{
	nd->nid = nd->sbi->root_nid;

	while (*name == '/')
		name++;

	/* At this point we know we have a real path component. */
	while (*name != '\0') {
		const char *p = name;
		int ret;

		do {
			++p;
		} while (*p != '\0' && *p != '/');

		DBG_BUGON(p <= name);
		ret = erofs_namei(nd, name, p - name);
		if (ret)
			return ret;

		/* Skip until no more slashes. */
		for (name = p; *name == '/'; ++name)
			;
	}
	return 0;
}

int erofs_ilookup(const char *path, struct erofs_inode *vi)
{
	int ret;
	struct nameidata nd = { .sbi = vi->sbi };

	ret = link_path_walk(path, &nd);
	if (ret)
		return ret;

	vi->nid = nd.nid;
	return erofs_read_inode_from_disk(vi);
}
