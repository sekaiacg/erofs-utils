// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C), 2022, Coolpad Group Limited.
 * Created by Yue Hu <huyue2@coolpad.com>
 */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include "erofs/err.h"
#include "erofs/inode.h"
#include "erofs/compress.h"
#include "erofs/print.h"
#include "erofs/internal.h"
#include "erofs/fragments.h"
#include "erofs/bitops.h"
#include "erofs/lock.h"
#include "liberofs_private.h"
#ifdef HAVE_SYS_SENDFILE_H
#include <sys/sendfile.h>
#endif

struct erofs_fragmentitem {
	struct list_head	list;
	u8			*data;
	erofs_off_t		length, pos;
};

#define EROFS_FRAGMENT_INMEM_SZ_MAX	(256 * 1024)
#define EROFS_TOF_HASHLEN		64

#define FRAGMENT_HASHSIZE		65536
#define FRAGMENT_HASH(c)		((c) & (FRAGMENT_HASHSIZE - 1))

struct erofs_fragment_bucket {
	struct list_head hash;
	erofs_rwsem_t lock;
};

struct erofs_packed_inode {
	struct erofs_fragment_bucket *bks;
	int fd;
	unsigned long *uptodate;
	erofs_mutex_t mutex;
	u64 uptodate_bits;
};

const char *erofs_frags_packedname = "packed_file";

u32 z_erofs_fragments_tofh(struct erofs_inode *inode, int fd, erofs_off_t fpos)
{
	u8 data_to_hash[EROFS_TOF_HASHLEN];
	u32 hash;
	int ret;

	if (inode->i_size <= EROFS_TOF_HASHLEN)
		return ~0U;

	ret = pread(fd, data_to_hash, EROFS_TOF_HASHLEN,
		    fpos + inode->i_size - EROFS_TOF_HASHLEN);
	if (ret < 0)
		return -errno;
	if (ret != EROFS_TOF_HASHLEN) {
		DBG_BUGON(1);
		return -EIO;
	}
	hash = erofs_crc32c(~0, data_to_hash, EROFS_TOF_HASHLEN);
	return hash != ~0U ? hash : 0;
}

static erofs_off_t erofs_fragment_longmatch(struct erofs_inode *inode,
					    struct erofs_fragmentitem *fi,
					    erofs_off_t matched, int fd)
{
	struct erofs_packed_inode *epi = inode->sbi->packedinode;
	erofs_off_t total = min_t(erofs_off_t, fi->length, inode->i_size);
	erofs_off_t pos;
	bool inmem = false;

	if (!fi->pos) {
		inmem = true;
		pos = fi->length - matched;
	} else {
		pos = fi->pos - matched;
	}

	while (matched < total) {
		char buf[2][16384];
		unsigned int sz;

		if (__erofs_unlikely(!inmem && pos <= total - matched)) {
			DBG_BUGON(1);
			return matched;
		}
		sz = min_t(u64, total - matched, sizeof(buf[0]));
		if (pread(fd, buf[0], sz, inode->i_size - matched - sz) != sz)
			break;

		if (!inmem) {
			if (pread(epi->fd, buf[1], sz, pos - sz) != sz)
				break;
			if (memcmp(buf[0], buf[1], sz))
				break;
		} else if (memcmp(buf[0], fi->data + pos - sz, sz)) {
			break;
		}
		pos -= sz;
		matched += sz;
	}
	return matched;
}

int erofs_fragment_findmatch(struct erofs_inode *inode, int fd, u32 tofh)
{
	struct erofs_packed_inode *epi = inode->sbi->packedinode;
	struct erofs_fragmentitem *cur, *fi = NULL;
	struct erofs_fragment_bucket *bk = &epi->bks[FRAGMENT_HASH(tofh)];
	unsigned int s1, e1;
	erofs_off_t deduped;
	u8 *data;
	int ret;

	if (inode->i_size <= EROFS_TOF_HASHLEN)
		return 0;
	if (list_empty(&bk->hash))
		return 0;

	s1 = min_t(u64, EROFS_FRAGMENT_INMEM_SZ_MAX, inode->i_size);
	data = malloc(s1);
	if (!data)
		return -ENOMEM;

	ret = pread(fd, data, s1, inode->i_size - s1);
	if (ret != s1) {
		free(data);
		return -errno;
	}
	e1 = s1 - EROFS_TOF_HASHLEN;
	deduped = 0;

	erofs_down_read(&bk->lock);
	list_for_each_entry(cur, &bk->hash, list) {
		unsigned int e2, mn;
		erofs_off_t inmax, i;

		DBG_BUGON(cur->length <= EROFS_TOF_HASHLEN);
		if (cur->pos)
			inmax = min_t(u64, cur->length,
				      EROFS_FRAGMENT_INMEM_SZ_MAX);
		else
			inmax = cur->length;
		e2 = inmax - EROFS_TOF_HASHLEN;
		if (memcmp(data + e1, cur->data + e2, EROFS_TOF_HASHLEN))
			continue;

		i = 0;
		mn = min(e1, e2);
		while (i < mn && cur->data[e2 - i - 1] == data[e1 - i - 1])
			++i;

		i += EROFS_TOF_HASHLEN;
		if (i >= s1) {		/* full short match */
			DBG_BUGON(i > s1);
			i = erofs_fragment_longmatch(inode, cur, s1, fd);
		}

		if (i <= deduped)
			continue;
		fi = cur;
		deduped = i;
		if (deduped == inode->i_size)
			break;
	}
	erofs_up_read(&bk->lock);
	free(data);
	if (deduped) {
		DBG_BUGON(!fi);
		inode->fragment_size = deduped;
		inode->fragment = fi;
		erofs_dbg("Dedupe %llu tail data of %s",
			  inode->fragment_size | 0ULL, inode->i_srcpath);
	}
	return 0;
}

int erofs_fragment_pack(struct erofs_inode *inode, void *data,
			erofs_off_t pos, erofs_off_t len, u32 tofh, bool tail)
{
	struct erofs_packed_inode *epi = inode->sbi->packedinode;
	struct erofs_fragment_bucket *bk = &epi->bks[FRAGMENT_HASH(tofh)];
	struct erofs_fragmentitem *fi;
	bool inmem = (pos == ~0ULL);

	fi = malloc(sizeof(*fi));
	if (!fi)
		return -ENOMEM;
	fi->length = len;
	if (!inmem) {
		pos += len;
		if (len > EROFS_FRAGMENT_INMEM_SZ_MAX) {
			if (!tail)
				data += len - EROFS_FRAGMENT_INMEM_SZ_MAX;
			len = EROFS_FRAGMENT_INMEM_SZ_MAX;
		}
	}

	fi->data = malloc(len);
	if (!fi->data) {
		free(fi);
		return -ENOMEM;
	}
	memcpy(fi->data, data, len);
	fi->pos = inmem ? 0 : pos;
	if (len > EROFS_TOF_HASHLEN) {
		list_add_tail(&fi->list, &bk->hash);
	} else {
		init_list_head(&fi->list);
	}
	inode->fragment = fi;
	inode->fragment_size = fi->length;
	erofs_dbg("Recording %llu fragment data of %s",
		  fi->length | 0ULL, inode->i_srcpath);
	return 0;
}

int erofs_pack_file_from_fd(struct erofs_inode *inode, int fd, u32 tofh)
{
	struct erofs_packed_inode *epi = inode->sbi->packedinode;
	s64 offset, rc, sz;
	char *memblock;
	bool onheap = false;

	if (__erofs_unlikely(!inode->i_size))
		return 0;

	offset = lseek(epi->fd, 0, SEEK_CUR);
	if (offset < 0)
		return -errno;

	memblock = mmap(NULL, inode->i_size, PROT_READ, MAP_SHARED, fd, 0);
	if (memblock == MAP_FAILED || !memblock) {
		erofs_off_t remaining = inode->i_size;
		struct erofs_vfile vin = { .fd = fd };

#if defined(HAVE_SYS_SENDFILE_H) && defined(HAVE_SENDFILE)
		do {
			sz = min_t(u64, remaining, UINT_MAX);
			rc = sendfile(epi->fd, fd, NULL, sz);
			if (rc <= 0)
				break;
			remaining -= rc;
		} while (remaining);
#endif
		while (remaining) {
			char buf[32768];

			sz = min_t(u64, remaining, sizeof(buf));
			rc = erofs_io_read(&vin, buf, sz);
			if (rc < 0)
				goto out;
			if (rc > 0) {
				rc = write(epi->fd, buf, rc);
				if (rc < 0)
					goto out;
			}
			remaining -= rc;
		}

		sz = min_t(u64, inode->i_size, EROFS_FRAGMENT_INMEM_SZ_MAX);
		memblock = malloc(sz);
		if (!memblock) {
			rc = -ENOMEM;
			goto out;
		}
		onheap = true;

		rc = pread(epi->fd, memblock, sz, offset + inode->i_size - sz);
		if (rc != sz) {
			if (rc >= 0) {
				DBG_BUGON(1);
				rc = -EIO;
			}
			goto out;
		}

		rc = lseek(fd, 0, SEEK_SET);
		if (rc < 0) {
			rc = -errno;
			goto out;
		}
	} else {
		rc = __erofs_io_write(epi->fd, memblock, inode->i_size);
		if (rc != inode->i_size) {
			if (rc >= 0)
				rc = -EIO;
			goto out;
		}
	}

	rc = erofs_fragment_pack(inode, memblock, offset, inode->i_size,
				 tofh, onheap);
out:
	if (onheap)
		free(memblock);
	else if (memblock)
		munmap(memblock, inode->i_size);
	return rc;
}

int erofs_fragment_commit(struct erofs_inode *inode, u32 tofh)
{
	struct erofs_packed_inode *epi = inode->sbi->packedinode;
	struct erofs_fragmentitem *fi = inode->fragment;
	erofs_off_t len = inode->fragment_size;
	unsigned int sz;
	s64 offset;
	int ret;

	if (!len) {
		DBG_BUGON(fi);
		return 0;
	}

	if (fi->pos) {
		inode->fragmentoff = fi->pos - len;
		return 0;
	}

	offset = lseek(epi->fd, 0, SEEK_CUR);
	if (offset < 0)
		return -errno;

	ret = write(epi->fd, fi->data, fi->length);
	if (ret != fi->length) {
		if (ret < 0)
			return -errno;
		return -EIO;
	}
	offset += fi->length;

	if (!list_empty(&fi->list)) {
		struct erofs_fragment_bucket *bk = &epi->bks[FRAGMENT_HASH(tofh)];
		void *nb;

		sz = min_t(u64, fi->length, EROFS_FRAGMENT_INMEM_SZ_MAX);

		erofs_down_write(&bk->lock);
		memmove(fi->data, fi->data + fi->length - sz, sz);

		nb = realloc(fi->data, sz);
		if (!nb) {
			erofs_up_write(&bk->lock);
			fi->data = NULL;
			return -ENOMEM;
		}
		fi->data = nb;
		fi->pos = (erofs_off_t)offset;
		erofs_up_write(&bk->lock);
		inode->fragmentoff = fi->pos - len;
		return 0;
	}
	inode->fragmentoff = (erofs_off_t)offset - len;
	free(fi->data);
	free(fi);
	return 0;
}

int erofs_flush_packed_inode(struct erofs_sb_info *sbi)
{
	struct erofs_packed_inode *epi = sbi->packedinode;
	struct erofs_inode *inode;

	if (!epi || !erofs_sb_has_fragments(sbi))
		return -EINVAL;

	if (lseek(epi->fd, 0, SEEK_CUR) <= 0)
		return 0;
	inode = erofs_mkfs_build_special_from_fd(sbi, epi->fd,
						 EROFS_PACKED_INODE);
	sbi->packed_nid = erofs_lookupnid(inode);
	erofs_iput(inode);
	return 0;
}

int erofs_packedfile(struct erofs_sb_info *sbi)
{
	return sbi->packedinode->fd;
}

void erofs_packedfile_exit(struct erofs_sb_info *sbi)
{
	struct erofs_packed_inode *epi = sbi->packedinode;
	struct erofs_fragmentitem *fi, *n;
	struct erofs_fragment_bucket *bk;

	if (!epi)
		return;

	if (epi->uptodate)
		free(epi->uptodate);

	if (epi->bks) {
		for (bk = epi->bks; bk < &epi->bks[FRAGMENT_HASHSIZE]; ++bk) {
			list_for_each_entry_safe(fi, n, &bk->hash, list) {
				free(fi->data);
				free(fi);
			}
		}
		free(epi->bks);
	}

	if (epi->fd >= 0)
		close(epi->fd);
	free(epi);
	sbi->packedinode = NULL;
}

int erofs_packedfile_init(struct erofs_sb_info *sbi, bool fragments_mkfs)
{
	struct erofs_packed_inode *epi;
	int err, i;

	if (sbi->packedinode)
		return -EINVAL;

	epi = calloc(1, sizeof(*epi));
	if (!epi)
		return -ENOMEM;

	sbi->packedinode = epi;
	if (fragments_mkfs) {
		epi->bks = malloc(sizeof(*epi->bks) * FRAGMENT_HASHSIZE);
		if (!epi->bks) {
			err = -ENOMEM;
			goto err_out;
		}
		for (i = 0; i < FRAGMENT_HASHSIZE; ++i) {
			init_list_head(&epi->bks[i].hash);
			erofs_init_rwsem(&epi->bks[i].lock);
		}
	}

	epi->fd = erofs_tmpfile();
	if (epi->fd < 0) {
		err = epi->fd;
		goto err_out;
	}

	if (erofs_sb_has_fragments(sbi) && sbi->packed_nid > 0) {
		struct erofs_inode ei = {
			.sbi = sbi,
			.nid = sbi->packed_nid,
		};
		s64 offset;

		err = erofs_read_inode_from_disk(&ei);
		if (err) {
			erofs_err("failed to read packed inode from disk: %s",
				  erofs_strerror(-errno));
			goto err_out;
		}

		offset = lseek(epi->fd, ei.i_size, SEEK_SET);
		if (offset < 0) {
			err = -errno;
			goto err_out;
		}
		epi->uptodate_bits = round_up(BLK_ROUND_UP(sbi, ei.i_size),
					      sizeof(epi->uptodate) * 8);
		epi->uptodate = calloc(1, epi->uptodate_bits >> 3);
		if (!epi->uptodate) {
			err = -ENOMEM;
			goto err_out;
		}
		erofs_mutex_init(&epi->mutex);
	}
	return 0;

err_out:
	erofs_packedfile_exit(sbi);
	return err;
}

static int erofs_load_packedinode_from_disk(struct erofs_inode *pi)
{
	struct erofs_sb_info *sbi = pi->sbi;
	int err;

	if (pi->nid)
		return 0;

	pi->nid = sbi->packed_nid;
	err = erofs_read_inode_from_disk(pi);
	if (err) {
		erofs_err("failed to read packed inode from disk: %s",
			  erofs_strerror(err));
		return err;
	}
	return 0;
}

static void *erofs_packedfile_preload(struct erofs_inode *pi,
				      struct erofs_map_blocks *map)
{
	struct erofs_sb_info *sbi = pi->sbi;
	struct erofs_packed_inode *epi = sbi->packedinode;
	unsigned int bsz = erofs_blksiz(sbi);
	struct erofs_vfile vf;
	char *buffer;
	erofs_off_t pos, end;
	ssize_t err;

	err = erofs_load_packedinode_from_disk(pi);
	if (err)
		return ERR_PTR(err);

	pos = map->m_la;
	err = erofs_map_blocks(pi, map, EROFS_GET_BLOCKS_FIEMAP);
	if (err)
		return ERR_PTR(err);

	end = round_up(map->m_la + map->m_llen, bsz);
	if (map->m_la < pos)
		map->m_la = round_up(map->m_la, bsz);
	else
		DBG_BUGON(map->m_la > pos);

	err = erofs_iopen(&vf, pi);
	if (err)
		return ERR_PTR(err);

	map->m_llen = end - map->m_la;
	DBG_BUGON(!map->m_llen);
	buffer = malloc(map->m_llen);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	err = erofs_pread(&vf, buffer, map->m_llen, map->m_la);
	if (err)
		goto err_out;

	err = pwrite(epi->fd, buffer, map->m_llen, map->m_la);
	if (err < 0) {
		err = -errno;
		if (err == -ENOSPC) {
			memset(epi->uptodate, 0, epi->uptodate_bits >> 3);
			(void)!ftruncate(epi->fd, 0);
		}
		goto err_out;
	}
	if (err != map->m_llen) {
		err = -EIO;
		goto err_out;
	}
	for (pos = map->m_la; pos < end; pos += bsz)
		__erofs_set_bit(erofs_blknr(sbi, pos), epi->uptodate);
	return buffer;

err_out:
	free(buffer);
	map->m_llen = 0;
	return ERR_PTR(err);
}

int erofs_packedfile_read(struct erofs_sb_info *sbi,
			  void *buf, erofs_off_t len, erofs_off_t pos)
{
	struct erofs_packed_inode *epi = sbi->packedinode;
	struct erofs_inode pi = {
		.sbi = sbi,
	};
	struct erofs_map_blocks map = { .buf = __EROFS_BUF_INITIALIZER };
	unsigned int bsz = erofs_blksiz(sbi);
	erofs_off_t end = pos + len;
	struct erofs_vfile vf;
	char *buffer = NULL;
	int err;

	if (!epi) {
		err = erofs_load_packedinode_from_disk(&pi);
		if (!err) {
			err = erofs_iopen(&vf, &pi);
			if (!err)
				err = erofs_pread(&vf, buf, len, pos);
		}
		return err;
	}

	err = 0;
	while (pos < end) {
		if (pos >= map.m_la && pos < map.m_la + map.m_llen) {
			len = min_t(erofs_off_t, end - pos,
				    map.m_la + map.m_llen - pos);
			memcpy(buf, buffer + pos - map.m_la, len);
		} else {
			erofs_blk_t bnr = erofs_blknr(sbi, pos);
			bool uptodate;

			if (__erofs_unlikely(bnr >= epi->uptodate_bits)) {
				erofs_err("packed inode EOF exceeded @ %llu",
					  pos | 0ULL);
				return -EFSCORRUPTED;
			}
			map.m_la = round_down(pos, bsz);
			len = min_t(erofs_off_t, bsz - (pos & (bsz - 1)),
				    end - pos);
			uptodate = __erofs_test_bit(bnr, epi->uptodate);
			if (!uptodate) {
#if EROFS_MT_ENABLED
				erofs_mutex_lock(&epi->mutex);
				uptodate = __erofs_test_bit(bnr, epi->uptodate);
				if (!uptodate) {
#endif
					free(buffer);
					buffer = erofs_packedfile_preload(&pi, &map);
					if (IS_ERR(buffer)) {
						erofs_mutex_unlock(&epi->mutex);
						buffer = NULL;
						goto fallback;
					}

#if EROFS_MT_ENABLED
				}
				erofs_mutex_unlock(&epi->mutex);
#endif
			}

			if (!uptodate)
				continue;

			err = pread(epi->fd, buf, len, pos);
			if (err < 0)
				break;
			if (err == len) {
				err = 0;
			} else {
fallback:
				err = erofs_load_packedinode_from_disk(&pi);
				if (err)
					break;
				err = erofs_iopen(&vf, &pi);
				if (!err)
					err = erofs_pread(&vf, buf, len, pos);
				if (err)
					break;
			}
			map.m_llen = 0;
		}
		buf += len;
		pos += len;
	}
	free(buffer);
	return err;
}
