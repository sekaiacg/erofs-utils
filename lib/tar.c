// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "erofs/print.h"
#include "erofs/diskbuf.h"
#include "erofs/inode.h"
#include "erofs/list.h"
#include "erofs/tar.h"
#include "erofs/xattr.h"
#include "erofs/blobchunk.h"
#include "erofs/rebuild.h"
#include "erofs/importer.h"
#if defined(HAVE_ZLIB)
#include <zlib.h>
#endif
#include "liberofs_base64.h"
#include "liberofs_cache.h"
#include "liberofs_gzran.h"

/* This file is a tape/volume header.  Ignore it on extraction.  */
#define GNUTYPE_VOLHDR 'V'

struct tar_header {
	char name[100];		/*   0-99 */
	char mode[8];		/* 100-107 */
	char uid[8];		/* 108-115 */
	char gid[8];		/* 116-123 */
	char size[12];		/* 124-135 */
	char mtime[12];		/* 136-147 */
	char chksum[8];		/* 148-155 */
	char typeflag;		/* 156-156 */
	char linkname[100];	/* 157-256 */
	char magic[6];		/* 257-262 */
	char version[2];	/* 263-264 */
	char uname[32];		/* 265-296 */
	char gname[32];		/* 297-328 */
	char devmajor[8];	/* 329-336 */
	char devminor[8];	/* 337-344 */
	char prefix[155];	/* 345-499 */
	char padding[12];	/* 500-512 (pad to exactly the 512 byte) */
};

#ifdef HAVE_LIBLZMA
#include <lzma.h>
struct erofs_iostream_liblzma {
	u8 inbuf[32768];
	lzma_stream strm;
	int fd;
};
#endif

void erofs_iostream_close(struct erofs_iostream *ios)
{
	free(ios->buffer);
	if (ios->decoder == EROFS_IOS_DECODER_GZIP) {
#if defined(HAVE_ZLIB)
		gzclose(ios->handler);
#endif
		return;
	} else if (ios->decoder == EROFS_IOS_DECODER_LIBLZMA) {
#if defined(HAVE_LIBLZMA)
		lzma_end(&ios->lzma->strm);
		close(ios->lzma->fd);
		free(ios->lzma);
#endif
		return;
	} else if (ios->decoder == EROFS_IOS_DECODER_GZRAN) {
		erofs_gzran_builder_final(ios->gb);
		return;
	}
	erofs_io_close(&ios->vf);
}

int erofs_iostream_open(struct erofs_iostream *ios, int fd, int decoder)
{
	s64 fsz;

	ios->feof = false;
	ios->tail = ios->head = 0;
	ios->decoder = decoder;
	ios->dumpfd = -1;
	if (decoder == EROFS_IOS_DECODER_GZIP) {
#if defined(HAVE_ZLIB)
		ios->handler = gzdopen(fd, "r");
		if (!ios->handler)
			return -ENOMEM;
		ios->sz = fsz = 0;
		ios->bufsize = 32768;
#else
		return -EOPNOTSUPP;
#endif
	} else if (decoder == EROFS_IOS_DECODER_LIBLZMA) {
#ifdef HAVE_LIBLZMA
		lzma_ret ret;

		ios->lzma = malloc(sizeof(*ios->lzma));
		if (!ios->lzma)
			return -ENOMEM;
		ios->lzma->fd = fd;
		ios->lzma->strm = (lzma_stream)LZMA_STREAM_INIT;
		ret = lzma_auto_decoder(&ios->lzma->strm,
					UINT64_MAX, LZMA_CONCATENATED);
		if (ret != LZMA_OK)
			return -EFAULT;
		ios->sz = fsz = 0;
		ios->bufsize = 32768;
#else
		return -EOPNOTSUPP;
#endif
	} else if (decoder == EROFS_IOS_DECODER_GZRAN) {
		ios->vf.fd = fd;
		ios->feof = false;
		ios->sz = 0;
		ios->bufsize = EROFS_GZRAN_WINSIZE * 2;
		ios->gb = erofs_gzran_builder_init(&ios->vf, 4194304);
		if (IS_ERR(ios->gb))
			return PTR_ERR(ios->gb);
	} else {
		ios->vf.fd = fd;
		fsz = lseek(fd, 0, SEEK_END);
		if (fsz <= 0) {
			ios->feof = !fsz;
			ios->sz = 0;
		} else {
			ios->sz = fsz;
			if (lseek(fd, 0, SEEK_SET))
				return -EIO;
#ifdef HAVE_POSIX_FADVISE
			if (posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL))
				erofs_warn("failed to fadvise: %s, ignored.",
					   erofs_strerror(-errno));
#endif
		}
		ios->bufsize = 32768;
	}

	do {
		ios->buffer = malloc(ios->bufsize);
		if (ios->buffer)
			break;
		ios->bufsize >>= 1;
	} while (ios->bufsize >= 1024);

	if (!ios->buffer)
		return -ENOMEM;
	return 0;
}

int erofs_iostream_read(struct erofs_iostream *ios, void **buf, u64 bytes)
{
	unsigned int rabytes = ios->tail - ios->head;
	int ret;

	if (rabytes >= bytes) {
		*buf = ios->buffer + ios->head;
		ios->head += bytes;
		return bytes;
	}

	if (ios->head) {
		memmove(ios->buffer, ios->buffer + ios->head, rabytes);
		ios->head = 0;
		ios->tail = rabytes;
	}

	if (!ios->feof) {
		if (ios->decoder == EROFS_IOS_DECODER_GZIP) {
#if defined(HAVE_ZLIB)
			ret = gzread(ios->handler, ios->buffer + rabytes,
				     ios->bufsize - rabytes);
			if (!ret) {
				int errnum;
				const char *errstr;

				errstr = gzerror(ios->handler, &errnum);
				if (errnum != Z_STREAM_END) {
					erofs_err("failed to gzread: %s", errstr);
					return -EIO;
				}
				ios->feof = true;
			}
			ios->tail += ret;
#else
			return -EOPNOTSUPP;
#endif
		} else if (ios->decoder == EROFS_IOS_DECODER_LIBLZMA) {
#ifdef HAVE_LIBLZMA
			struct erofs_iostream_liblzma *lzma = ios->lzma;
			lzma_action action = LZMA_RUN;
			lzma_ret ret2;

			if (!lzma->strm.avail_in) {
				lzma->strm.next_in = lzma->inbuf;
				ret = read(lzma->fd, lzma->inbuf,
					   sizeof(lzma->inbuf));
				if (ret < 0)
					return -errno;
				lzma->strm.avail_in = ret;
				if (ret < sizeof(lzma->inbuf))
					action = LZMA_FINISH;
			}
			lzma->strm.next_out = (u8 *)ios->buffer + rabytes;
			lzma->strm.avail_out = ios->bufsize - rabytes;

			ret2 = lzma_code(&lzma->strm, action);
			if (ret2 != LZMA_OK) {
				if (ret2 == LZMA_STREAM_END)
					ios->feof = true;
				else
					return -EIO;
			}
			ret = ios->bufsize - rabytes - lzma->strm.avail_out;
			ios->tail += ret;
#else
			return -EOPNOTSUPP;
#endif
		} else if (ios->decoder == EROFS_IOS_DECODER_GZRAN) {
			ret = erofs_gzran_builder_read(ios->gb, ios->buffer + rabytes);
			if (ret < 0)
				return ret;
			ios->tail += ret;
			DBG_BUGON(ios->tail > ios->bufsize);
			if (!ret)
				ios->feof = true;
		} else {
			ret = erofs_io_read(&ios->vf, ios->buffer + rabytes,
					    ios->bufsize - rabytes);
			if (ret < 0)
				return ret;
			ios->tail += ret;
			if (ret < ios->bufsize - rabytes)
				ios->feof = true;
		}
		if (__erofs_unlikely(ios->dumpfd >= 0))
			if (write(ios->dumpfd, ios->buffer + rabytes, ret) < ret)
				erofs_err("failed to dump %d bytes of the raw stream: %s",
					  ret, erofs_strerror(-errno));
	}
	*buf = ios->buffer;
	ret = min_t(int, ios->tail, min_t(u64, bytes, INT_MAX));
	ios->head = ret;
	return ret;
}

int erofs_iostream_bread(struct erofs_iostream *ios, void *buf, u64 bytes)
{
	u64 rem = bytes;
	void *src;
	int ret;

	do {
		ret = erofs_iostream_read(ios, &src, rem);
		if (ret < 0)
			return ret;
		memcpy(buf, src, ret);
		rem -= ret;
	} while (rem && ret);

	return bytes - rem;
}

int erofs_iostream_lskip(struct erofs_iostream *ios, u64 sz)
{
	unsigned int rabytes = ios->tail - ios->head;
	int ret;
	void *dummy;

	if (rabytes >= sz) {
		ios->head += sz;
		return 0;
	}

	sz -= rabytes;
	ios->head = ios->tail = 0;
	if (ios->feof)
		return sz;

	if (ios->sz && __erofs_likely(ios->dumpfd < 0)) {
		s64 cur = erofs_io_lseek(&ios->vf, sz, SEEK_CUR);

		if (cur > ios->sz)
			return cur - ios->sz;
		return 0;
	}

	do {
		ret = erofs_iostream_read(ios, &dummy, sz);
		if (ret < 0)
			return ret;
		sz -= ret;
	} while (!(ios->feof || !ret || !sz));

	return sz;
}

static long long tarerofs_otoi(const char *ptr, int len)
{
	char inp[32];
	char *endp = inp;
	long long val;

	memcpy(inp, ptr, len);
	inp[len] = '\0';

	errno = 0;
	val = strtoll(inp, &endp, 8);
	if ((*endp == '\0' && endp == inp) |
	    (*endp != '\0' && *endp != ' '))
		errno = EINVAL;
	return val;
}

static long long tarerofs_parsenum(const char *ptr, int len)
{
	errno = 0;
	/*
	 * For fields containing numbers or timestamps that are out of range
	 * for the basic format, the GNU format uses a base-256 representation
	 * instead of an ASCII octal number.
	 */
	if (*(char *)ptr == '\200' || *(char *)ptr == '\377') {
		long long res = 0;

		while (--len)
			res = (res << 8) | (u8)*(++ptr);
		return res;
	}
	return tarerofs_otoi(ptr, len);
}

struct tarerofs_xattr_item {
	struct list_head list;
	char *kv;
	unsigned int len, namelen;
};

int tarerofs_insert_xattr(struct list_head *xattrs,
			  char *kv, int namelen, int len, bool skip)
{
	struct tarerofs_xattr_item *item;
	char *nv;

	DBG_BUGON(namelen >= len);
	list_for_each_entry(item, xattrs, list) {
		if (!strncmp(item->kv, kv, namelen + 1)) {
			if (skip)
				return 0;
			goto found;
		}
	}

	item = malloc(sizeof(*item));
	if (!item)
		return -ENOMEM;
	item->kv = NULL;
	item->namelen = namelen;
	namelen = 0;
	list_add_tail(&item->list, xattrs);
found:
	nv = realloc(item->kv, len);
	if (!nv)
		return -ENOMEM;
	item->kv = nv;
	item->len = len;
	memcpy(nv + namelen, kv + namelen, len - namelen);
	return 0;
}

int tarerofs_merge_xattrs(struct list_head *dst, struct list_head *src)
{
	struct tarerofs_xattr_item *item;

	list_for_each_entry(item, src, list) {
		int ret;

		ret = tarerofs_insert_xattr(dst, item->kv, item->namelen,
					    item->len, true);
		if (ret)
			return ret;
	}
	return 0;
}

void tarerofs_remove_xattrs(struct list_head *xattrs)
{
	struct tarerofs_xattr_item *item, *n;

	list_for_each_entry_safe(item, n, xattrs, list) {
		DBG_BUGON(!item->kv);
		free(item->kv);
		list_del(&item->list);
		free(item);
	}
}

int tarerofs_apply_xattrs(struct erofs_inode *inode, struct list_head *xattrs)
{
	struct tarerofs_xattr_item *item;
	int ret;

	list_for_each_entry(item, xattrs, list) {
		const char *v = item->kv + item->namelen + 1;
		unsigned int vsz = item->len - item->namelen - 1;

		if (item->len <= item->namelen - 1) {
			DBG_BUGON(item->len < item->namelen - 1);
			continue;
		}
		item->kv[item->namelen] = '\0';
		erofs_dbg("Recording xattr(%s)=\"%s\" (of %u bytes) to file %s",
			  item->kv, v, vsz, inode->i_srcpath);
		ret = erofs_setxattr(inode, item->kv, v, vsz);
		if (ret == -ENODATA)
			erofs_err("Failed to set xattr(%s)=%s to file %s",
				  item->kv, v, inode->i_srcpath);
		else if (ret)
			return ret;
	}
	return 0;
}

static int tohex(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static unsigned int url_decode(char *str, unsigned int len)
{
	const char *s = str;
	char *d = str;
	int d1, d2;

	for (; len && *s != '\0' && *s != '%'; ++d, ++s, --len);
	if (!len || *s == '\0')
		return d - str;

	while (len && *s != '\0') {
		if (*s == '%' && len > 2) {
			/* Try to convert % escape */
			d1 = tohex(s[1]), d2 = tohex(s[2]);

			/* Look good, consume three chars */
			if (d1 >= 0 && d2 >= 0) {
				s += 3;
				len -= 3;
				*d++ = (d1 << 4) | d2;
				continue;
			}
			/* Otherwise, treat '%' as normal char */
		}
		*d++ = *s++;
		--len;
	}
	return d - str;
}

int tarerofs_parse_pax_header(struct erofs_iostream *ios,
			      struct erofs_pax_header *eh, u32 size)
{
	char *buf, *p;
	int ret;

	buf = malloc(size);
	if (!buf)
		return -ENOMEM;
	p = buf;

	ret = erofs_iostream_bread(ios, buf, size);
	if (ret != size)
		goto out;

	while (p < buf + size) {
		char *kv, *key, *value;
		int len, n;
		/* extended records are of the format: "LEN NAME=VALUE\n" */
		ret = sscanf(p, "%d %n", &len, &n);
		if (ret < 1 || len <= n || len > buf + size - p) {
			ret = -EIO;
			goto out;
		}
		kv = p + n;
		p += len;
		len -= n;

		if (p[-1] != '\n') {
			ret = -EIO;
			goto out;
		}
		p[-1] = '\0';

		value = memchr(kv, '=', p - kv);
		if (!value) {
			ret = -EIO;
			goto out;
		} else {
			long long lln;

			value++;

			if (!strncmp(kv, "path=", sizeof("path=") - 1)) {
				int j = p - 1 - value;
				free(eh->path);
				eh->path = strdup(value);
				while (eh->path[j - 1] == '/')
					eh->path[--j] = '\0';
			} else if (!strncmp(kv, "linkpath=",
					sizeof("linkpath=") - 1)) {
				free(eh->link);
				eh->link = strdup(value);
			} else if (!strncmp(kv, "mtime=",
					sizeof("mtime=") - 1)) {
				ret = sscanf(value, "%lld %n", &lln, &n);
				if(ret < 1) {
					ret = -EIO;
					goto out;
				}
				eh->st.st_mtime = lln;
				if (value[n] == '.') {
					ret = sscanf(value + n + 1, "%d", &n);
					if (ret < 1) {
						ret = -EIO;
						goto out;
					}
					ST_MTIM_NSEC_SET(&eh->st, n);
				} else {
					ST_MTIM_NSEC_SET(&eh->st, 0);
				}
				eh->use_mtime = true;
			} else if (!strncmp(kv, "size=",
					sizeof("size=") - 1)) {
				ret = sscanf(value, "%lld %n", &lln, &n);
				if(ret < 1 || value[n] != '\0') {
					ret = -EIO;
					goto out;
				}
				eh->st.st_size = lln;
				eh->use_size = true;
			} else if (!strncmp(kv, "uid=", sizeof("uid=") - 1)) {
				ret = sscanf(value, "%lld %n", &lln, &n);
				if(ret < 1 || value[n] != '\0') {
					ret = -EIO;
					goto out;
				}
				eh->st.st_uid = lln;
				eh->use_uid = true;
			} else if (!strncmp(kv, "gid=", sizeof("gid=") - 1)) {
				ret = sscanf(value, "%lld %n", &lln, &n);
				if(ret < 1 || value[n] != '\0') {
					ret = -EIO;
					goto out;
				}
				eh->st.st_gid = lln;
				eh->use_gid = true;
			} else if (!strncmp(kv, "SCHILY.xattr.",
				   sizeof("SCHILY.xattr.") - 1)) {
				key = kv + sizeof("SCHILY.xattr.") - 1;
				--len; /* p[-1] == '\0' */
				ret = tarerofs_insert_xattr(&eh->xattrs, key,
						value - key - 1,
						len - (key - kv), false);
				if (ret)
					goto out;
			} else if (!strncmp(kv, "LIBARCHIVE.xattr.",
				   sizeof("LIBARCHIVE.xattr.") - 1)) {
				int namelen;

				key = kv + sizeof("LIBARCHIVE.xattr.") - 1;
				namelen = url_decode(key, value - key - 1);
				--len; /* p[-1] == '\0' */
				ret = erofs_base64_decode(value,
						len - (value - kv), (u8 *)value);
				if (ret < 0) {
					ret = -EFSCORRUPTED;
					goto out;
				}

				if (namelen != value - key - 1) {
					key[namelen] = '=';
					memmove(key + namelen + 1, value, ret);
					value = key + namelen + 1;
				}
				ret = tarerofs_insert_xattr(&eh->xattrs, key,
						namelen, namelen + 1 + ret, false);
				if (ret)
					goto out;
			} else {
				erofs_info("unrecognized pax keyword \"%s\", ignoring", kv);
			}
		}
	}
	ret = 0;
out:
	free(buf);
	return ret;
}

void tarerofs_remove_inode(struct erofs_inode *inode)
{
	struct erofs_dentry *d;

	--inode->i_nlink;
	if (!S_ISDIR(inode->i_mode))
		return;

	/* remove all subdirss */
	list_for_each_entry(d, &inode->i_subdirs, d_child) {
		if (!is_dot_dotdot(d->name))
			tarerofs_remove_inode(d->inode);
		erofs_iput(d->inode);
		d->inode = NULL;
	}
	--inode->i_parent->i_nlink;
}

static int tarerofs_write_uncompressed_file(struct erofs_inode *inode,
					    struct erofs_tarfile *tar)
{
	struct erofs_sb_info *sbi = inode->sbi;
	erofs_blk_t nblocks;
	erofs_off_t pos;
	void *buf;
	int ret;

	inode->datalayout = EROFS_INODE_FLAT_PLAIN;
	nblocks = DIV_ROUND_UP(inode->i_size, 1U << sbi->blkszbits);

	ret = erofs_allocate_inode_bh_data(inode, nblocks);
	if (ret)
		return ret;

	for (pos = 0; pos < inode->i_size; pos += ret) {
		ret = erofs_iostream_read(&tar->ios, &buf, inode->i_size - pos);
		if (ret < 0)
			break;
		if (erofs_dev_write(sbi, buf,
				    erofs_pos(sbi, inode->u.i_blkaddr) + pos,
				    ret)) {
			ret = -EIO;
			break;
		}
	}
	inode->idata_size = 0;
	inode->datasource = EROFS_INODE_DATA_SOURCE_NONE;
	return 0;
}

static int tarerofs_write_file_data(struct erofs_inode *inode,
				    struct erofs_tarfile *tar)
{
	void *buf;
	int fd, nread;
	u64 off, j;

	if (!inode->i_diskbuf) {
		inode->i_diskbuf = calloc(1, sizeof(*inode->i_diskbuf));
		if (!inode->i_diskbuf)
			return -ENOSPC;
	} else {
		erofs_diskbuf_close(inode->i_diskbuf);
	}

	fd = erofs_diskbuf_reserve(inode->i_diskbuf, 0, &off);
	if (fd < 0)
		return -EBADF;

	for (j = inode->i_size; j; ) {
		nread = erofs_iostream_read(&tar->ios, &buf, j);
		if (nread < 0)
			break;
		if (pwrite(fd, buf, nread, off) != nread) {
			nread = -EIO;
			break;
		}
		j -= nread;
		off += nread;
	}
	erofs_diskbuf_commit(inode->i_diskbuf, inode->i_size);
	inode->datasource = EROFS_INODE_DATA_SOURCE_DISKBUF;
	return 0;
}

int tarerofs_parse_tar(struct erofs_importer *im, struct erofs_tarfile *tar)
{
	struct erofs_pax_header eh = tar->global;
	struct erofs_importer_params *params = im->params;
	struct erofs_sb_info *sbi = im->sbi;
	struct erofs_inode *root = im->root;
	bool whout, opq, e = false;
	char _path[PATH_MAX + 1], *path = _path + 1;
	struct stat st;
	mode_t mode;
	erofs_off_t tar_offset, dataoff;

	struct tar_header *th;
	struct erofs_dentry *d;
	struct erofs_inode *inode;
	unsigned int csum, cksum;
	int ckksum, ret, rem, j;

	root->dev = tar->dev;
	if (eh.path)
		eh.path = strdup(eh.path);
	if (eh.link)
		eh.link = strdup(eh.link);
	init_list_head(&eh.xattrs);

restart:
	rem = tar->offset & 511;
	if (rem) {
		if (erofs_iostream_lskip(&tar->ios, 512 - rem)) {
			ret = -EIO;
			goto out;
		}
		tar->offset += 512 - rem;
	}

	tar_offset = tar->offset;
	ret = erofs_iostream_read(&tar->ios, (void **)&th, sizeof(*th));
	if (ret != sizeof(*th)) {
		if (tar->headeronly_mode || tar->ddtaridx_mode) {
			ret = 1;
			goto out;
		}
		erofs_err("failed to read header block @ %llu", tar_offset);
		ret = -EIO;
		goto out;
	}
	tar->offset += sizeof(*th);

	/* chksum field itself treated as ' ' */
	csum = tarerofs_otoi(th->chksum, sizeof(th->chksum));
	if (errno) {
		if (*th->name == '\0') {
out_eot:
			if (e) {	/* end of tar 2 empty blocks */
				ret = 1;
				goto out;
			}
			e = true;	/* empty jump to next block */
			goto restart;
		}
		erofs_err("invalid chksum @ %llu", tar_offset);
		ret = -EBADMSG;
		goto out;
	}
	cksum = 0;
	for (j = 0; j < 8; ++j)
		cksum += (unsigned int)' ';
	ckksum = cksum;
	for (j = 0; j < 148; ++j) {
		cksum += (unsigned int)((u8*)th)[j];
		ckksum += (int)((char*)th)[j];
	}
	for (j = 156; j < 500; ++j) {
		cksum += (unsigned int)((u8*)th)[j];
		ckksum += (int)((char*)th)[j];
	}
	if (!tar->ddtaridx_mode && csum != cksum && csum != ckksum) {
		/* should not bail out here, just in case */
		if (*th->name == '\0') {
			DBG_BUGON(1);
			goto out_eot;
		}
		erofs_err("chksum mismatch @ %llu", tar_offset);
		ret = -EBADMSG;
		goto out;
	}

	if (th->typeflag == GNUTYPE_VOLHDR) {
		if (th->size[0])
			erofs_warn("GNUTYPE_VOLHDR with non-zeroed size @ %llu",
				   tar_offset);
		/* anyway, strncpy could cause some GCC warning here */
		memcpy(sbi->volume_name, th->name, sizeof(sbi->volume_name));
		goto restart;
	}

	if (memcmp(th->magic, "ustar", 5)) {
		erofs_err("invalid tar magic @ %llu", tar_offset);
		ret = -EIO;
		goto out;
	}

	if (eh.use_size) {
		st.st_size = eh.st.st_size;
	} else {
		st.st_size = tarerofs_parsenum(th->size, sizeof(th->size));
		if (errno)
			goto invalid_tar;
	}

	if (th->typeflag <= '7' && !eh.path) {
		eh.path = path;
		j = 0;
		if (*th->prefix) {
			memcpy(path, th->prefix, sizeof(th->prefix));
			path[sizeof(th->prefix)] = '\0';
			j = strlen(path);
			if (path[j - 1] != '/') {
				path[j] = '/';
				path[++j] = '\0';
			}
		}
		memcpy(path + j, th->name, sizeof(th->name));
		path[j + sizeof(th->name)] = '\0';
		j = strlen(path);
		if (__erofs_unlikely(!j)) {
			erofs_info("substituting '.' for empty filename");
			path[0] = '.';
			path[1] = '\0';
		} else {
			*_path = '\0';
			while (path[j - 1] == '/')
				path[--j] = '\0';
		}
	}

	dataoff = tar->offset;
	tar->offset += st.st_size;
	st.st_mode = 0;
	switch(th->typeflag) {
	case '0':
	case '7':
	case '1':
		st.st_mode = S_IFREG;
		if (tar->headeronly_mode || tar->ddtaridx_mode)
			tar->offset -= st.st_size;
		break;
	case '2':
		st.st_mode = S_IFLNK;
		break;
	case '3':
		st.st_mode = S_IFCHR;
		break;
	case '4':
		st.st_mode = S_IFBLK;
		break;
	case '5':
		st.st_mode = S_IFDIR;
		break;
	case '6':
		st.st_mode = S_IFIFO;
		break;
	case 'g':
		ret = tarerofs_parse_pax_header(&tar->ios, &tar->global,
						st.st_size);
		if (ret)
			goto out;
		if (tar->global.path) {
			free(eh.path);
			eh.path = strdup(tar->global.path);
		}
		if (tar->global.link) {
			free(eh.link);
			eh.link = strdup(tar->global.link);
		}
		goto restart;
	case 'x':
		ret = tarerofs_parse_pax_header(&tar->ios, &eh, st.st_size);
		if (ret)
			goto out;
		goto restart;
	case 'L':
		free(eh.path);
		eh.path = malloc(st.st_size + 1);
		if (st.st_size != erofs_iostream_bread(&tar->ios, eh.path,
						       st.st_size))
			goto invalid_tar;
		eh.path[st.st_size] = '\0';
		goto restart;
	case 'K':
		free(eh.link);
		eh.link = malloc(st.st_size + 1);
		if (st.st_size > PATH_MAX || st.st_size !=
		    erofs_iostream_bread(&tar->ios, eh.link, st.st_size))
			goto invalid_tar;
		eh.link[st.st_size] = '\0';
		goto restart;
	default:
		erofs_info("unrecognized typeflag %xh @ %llu - ignoring",
			   th->typeflag, tar_offset);
		(void)erofs_iostream_lskip(&tar->ios, st.st_size);
		ret = 0;
		goto out;
	}

	mode = tarerofs_otoi(th->mode, sizeof(th->mode));
	if (errno)
		goto invalid_tar;
	if (__erofs_unlikely(mode & S_IFMT) &&
	    (mode & S_IFMT) != (st.st_mode & S_IFMT))
		erofs_warn("invalid ustar mode %05o @ %llu", mode, tar_offset);
	st.st_mode |= mode & ~S_IFMT;

	if (eh.use_uid) {
		st.st_uid = eh.st.st_uid;
	} else {
		st.st_uid = tarerofs_parsenum(th->uid, sizeof(th->uid));
		if (errno)
			goto invalid_tar;
	}

	if (eh.use_gid) {
		st.st_gid = eh.st.st_gid;
	} else {
		st.st_gid = tarerofs_parsenum(th->gid, sizeof(th->gid));
		if (errno)
			goto invalid_tar;
	}

	if (eh.use_mtime) {
		st.st_mtime = eh.st.st_mtime;
		ST_MTIM_NSEC_SET(&st, ST_MTIM_NSEC(&eh.st));
	} else {
		st.st_mtime = tarerofs_parsenum(th->mtime, sizeof(th->mtime));
		if (errno)
			goto invalid_tar;
		ST_MTIM_NSEC_SET(&st, 0);
	}

	st.st_rdev = 0;
	if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) {
		int major, minor;

		major = tarerofs_parsenum(th->devmajor, sizeof(th->devmajor));
		if (errno) {
			erofs_err("invalid device major @ %llu", tar_offset);
			goto out;
		}

		minor = tarerofs_parsenum(th->devminor, sizeof(th->devminor));
		if (errno) {
			erofs_err("invalid device minor @ %llu", tar_offset);
			goto out;
		}

		st.st_rdev = (major << 8) | (minor & 0xff) | ((minor & ~0xff) << 12);
	} else if (th->typeflag == '1' || th->typeflag == '2') {
		if (!eh.link)
			eh.link = strndup(th->linkname, sizeof(th->linkname));
	}

	/* EROFS metadata index referring to the original tar data */
	if (tar->index_mode && sbi->extra_devices &&
	    erofs_blkoff(sbi, dataoff)) {
		erofs_err("invalid tar data alignment @ %llu", tar_offset);
		ret = -EIO;
		goto out;
	}

	erofs_dbg("parsing %s (mode %05o)", eh.path, st.st_mode);

	d = erofs_rebuild_get_dentry(root, eh.path, tar->aufs, &whout, &opq, true);
	if (IS_ERR(d)) {
		ret = PTR_ERR(d);
		goto out;
	}

	if (!d) {
		/* some tarballs include '.' which indicates the root directory */
		if (!S_ISDIR(st.st_mode)) {
			ret = -ENOTDIR;
			goto out;
		}
		inode = root;
	} else if (opq) {
		DBG_BUGON(d->type == EROFS_FT_UNKNOWN);
		DBG_BUGON(!d->inode);
		/*
		 * needed if the tar tree is used soon, thus we have no chance
		 * to generate it from xattrs.  No impact to mergefs.
		 */
		d->inode->opaque = true;
		ret = erofs_set_opaque_xattr(d->inode);
		goto out;
	} else if (th->typeflag == '1') {	/* hard link cases */
		struct erofs_dentry *d2;
		bool dumb;

		if (S_ISDIR(st.st_mode)) {
			ret = -EISDIR;
			goto out;
		}

		if (d->type != EROFS_FT_UNKNOWN) {
			tarerofs_remove_inode(d->inode);
			erofs_iput(d->inode);
		}
		d->inode = NULL;

		d2 = erofs_rebuild_get_dentry(root, eh.link, tar->aufs,
					      &dumb, &dumb, false);
		if (IS_ERR(d2)) {
			ret = PTR_ERR(d2);
			goto out;
		}
		if (d2->type == EROFS_FT_UNKNOWN) {
			ret = -ENOENT;
			goto out;
		}
		if (S_ISDIR(d2->inode->i_mode)) {
			ret = -EISDIR;
			goto out;
		}
		inode = erofs_igrab(d2->inode);
		d->inode = inode;
		d->type = d2->type;
		++inode->i_nlink;
		ret = 0;
		goto out;
	} else if (d->type != EROFS_FT_UNKNOWN) {
		if (d->type != EROFS_FT_DIR || !S_ISDIR(st.st_mode)) {
			struct erofs_inode *parent = d->inode->i_parent;

			tarerofs_remove_inode(d->inode);
			erofs_iput(d->inode);
			d->inode = parent;
			goto new_inode;
		}
		inode = d->inode;
	} else {
new_inode:
		inode = erofs_new_inode(sbi);
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			goto out;
		}
		inode->dev = tar->dev;
		inode->i_parent = d->inode;
		d->inode = inode;
		d->type = erofs_mode_to_ftype(st.st_mode);
	}

	if (whout) {
		inode->i_mode = (inode->i_mode & ~S_IFMT) | S_IFCHR;
		inode->u.i_rdev = EROFS_WHITEOUT_DEV;
		d->type = EROFS_FT_CHRDEV;

		/*
		 * Mark the parent directory as copied-up to avoid exposing
		 * whiteouts if mounted.  See kernel commit b79e05aaa166
		 * ("ovl: no direct iteration for dir with origin xattr")
		 */
		inode->i_parent->whiteouts = true;
	} else {
		inode->i_mode = st.st_mode;
		if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode))
			inode->u.i_rdev = erofs_new_encode_dev(st.st_rdev);
	}

	inode->i_srcpath = strdup(eh.path);
	if (!inode->i_srcpath) {
		ret = -ENOMEM;
		goto out;
	}

	ret = __erofs_fill_inode(im, inode, &st, eh.path);
	if (ret)
		goto out;
	inode->i_size = st.st_size;

	if (!S_ISDIR(inode->i_mode)) {
		if (S_ISLNK(inode->i_mode)) {
			inode->i_size = strlen(eh.link);
			inode->i_link = malloc(inode->i_size + 1);
			memcpy(inode->i_link, eh.link, inode->i_size + 1);
		} else if (inode->i_size) {
			if (tar->headeronly_mode) {
				ret = erofs_write_zero_inode(inode);
			} else if (tar->ddtaridx_mode) {
				dataoff = le64_to_cpu(*(__le64 *)(th->devmajor));
				if (tar->rvsp_mode) {
					inode->datasource = EROFS_INODE_DATA_SOURCE_RESVSP;
					inode->i_ino[1] = dataoff;
					ret = 0;
				} else {
					ret = tarerofs_write_chunkes(inode, dataoff);
				}
			} else if (tar->rvsp_mode) {
				inode->datasource = EROFS_INODE_DATA_SOURCE_RESVSP;
				inode->i_ino[1] = dataoff;
				if (erofs_iostream_lskip(&tar->ios, inode->i_size))
					ret = -EIO;
				else
					ret = 0;
			} else if (tar->index_mode) {
				ret = tarerofs_write_chunkes(inode, dataoff);
				if (!ret && erofs_iostream_lskip(&tar->ios,
								 inode->i_size))
					ret = -EIO;
			} else if (tar->try_no_reorder &&
				   !cfg.c_compr_opts[0].alg &&
				   params->no_datainline) {
				ret = tarerofs_write_uncompressed_file(inode, tar);
			} else {
				ret = tarerofs_write_file_data(inode, tar);
			}
			if (ret)
				goto out;
		}
		inode->i_nlink++;
	} else if (!inode->i_nlink) {
		inode->i_nlink = 2;
	}

	ret = tarerofs_merge_xattrs(&eh.xattrs, &tar->global.xattrs);
	if (ret)
		goto out;

	ret = tarerofs_apply_xattrs(inode, &eh.xattrs);

out:
	if (eh.path != path)
		free(eh.path);
	free(eh.link);
	tarerofs_remove_xattrs(&eh.xattrs);
	return ret;

invalid_tar:
	erofs_err("invalid tar @ %llu", tar_offset);
	ret = -EIO;
	goto out;
}
