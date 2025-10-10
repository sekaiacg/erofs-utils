// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "erofs/internal.h"
#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>
#endif
#ifdef HAVE_LINUX_FALLOC_H
#include <linux/falloc.h>
#endif
#ifdef HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif
#define EROFS_MODNAME	"erofs_io"
#include "erofs/print.h"

ssize_t __erofs_io_write(int fd, const void *buf, size_t len)
{
	ssize_t ret, written = 0;

	do {
		ret = write(fd, buf, len - written);
		if (ret <= 0) {
			if (!ret)
				break;
			if (errno != EINTR) {
				erofs_err("failed to write: %s", strerror(errno));
				return -errno;
			}
			ret = 0;
		}
		buf += ret;
		written += ret;
	} while (written < len);

	return written;
}

int erofs_io_fstat(struct erofs_vfile *vf, struct stat *buf)
{
	if (__erofs_unlikely(cfg.c_dry_run)) {
		buf->st_size = 0;
		buf->st_mode = S_IFREG | 0777;
		return 0;
	}

	if (vf->ops)
		return vf->ops->fstat(vf, buf);
	return fstat(vf->fd, buf);
}

ssize_t erofs_io_pwrite(struct erofs_vfile *vf, const void *buf,
			u64 pos, size_t len)
{
	ssize_t ret, written = 0;

	if (__erofs_unlikely(cfg.c_dry_run))
		return 0;

	if (vf->ops)
		return vf->ops->pwrite(vf, buf, pos, len);

	pos += vf->offset;
	do {
#ifdef HAVE_PWRITE64
		ret = pwrite64(vf->fd, buf, len, (off64_t)pos);
#else
		ret = pwrite(vf->fd, buf, len, (off_t)pos);
#endif
		if (ret <= 0) {
			if (!ret)
				break;
			if (errno != EINTR) {
				erofs_err("failed to write: %s", strerror(errno));
				return -errno;
			}
			ret = 0;
		}
		buf += ret;
		pos += ret;
		written += ret;
	} while (written < len);

	return written;
}

ssize_t erofs_io_pwritev(struct erofs_vfile *vf, const struct iovec *iov,
			 int iovcnt, u64 pos)
{
	ssize_t ret, written;
	int i;

	if (__erofs_unlikely(cfg.c_dry_run))
		return 0;

#ifdef HAVE_PWRITEV
	if (!vf->ops) {
		ret = pwritev(vf->fd, iov, iovcnt, pos + vf->offset);
		if (ret < 0)
			return -errno;
		return ret;
	}
#endif
	if (vf->ops && vf->ops->pwritev)
		return vf->ops->pwritev(vf, iov, iovcnt, pos);
	written = 0;
	for (i = 0; i < iovcnt; ++i) {
		ret = erofs_io_pwrite(vf, iov[i].iov_base, pos, iov[i].iov_len);
		if (ret < iov[i].iov_len) {
			if (ret < 0)
				return ret;
			return written + ret;
		}
		written += iov[i].iov_len;
		pos += iov[i].iov_len;
	}
	return written;
}

int erofs_io_fsync(struct erofs_vfile *vf)
{
	int ret;

	if (__erofs_unlikely(cfg.c_dry_run))
		return 0;

	if (vf->ops)
		return vf->ops->fsync(vf);

	ret = fsync(vf->fd);
	if (ret) {
		erofs_err("failed to fsync(!): %s", strerror(errno));
		return -errno;
	}
	return 0;
}

static const char erofs_zeroed[EROFS_MAX_BLOCK_SIZE];

int __erofs_0write(int fd, size_t len)
{
	int err = 0;

	while (len) {
		u32 count = min_t(u64, sizeof(erofs_zeroed), len);

		err = write(fd, erofs_zeroed, count);
		if (err <= 0) {
			if (err < 0)
				err = -errno;
			break;
		}
		len -= err;
	}
	return err < 0 ? err : len;
}

int erofs_io_fallocate(struct erofs_vfile *vf, u64 offset,
		       size_t len, bool zeroout)
{
	ssize_t ret;

	if (__erofs_unlikely(cfg.c_dry_run))
		return 0;

	if (vf->ops)
		return vf->ops->fallocate(vf, offset, len, zeroout);

#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_PUNCH_HOLE)
	if (!zeroout && fallocate(vf->fd, FALLOC_FL_PUNCH_HOLE |
		    FALLOC_FL_KEEP_SIZE, offset + vf->offset, len) >= 0)
		return 0;
#endif
	while (len > sizeof(erofs_zeroed)) {
		ret = erofs_io_pwrite(vf, erofs_zeroed, offset,
				      sizeof(erofs_zeroed));
		if (ret < 0)
			return (int)ret;
		len -= ret;
		offset += ret;
	}
	return erofs_io_pwrite(vf, erofs_zeroed, offset, len) == len ? 0 : -EIO;
}

int erofs_io_ftruncate(struct erofs_vfile *vf, u64 length)
{
	int ret;
	struct stat st;

	if (__erofs_unlikely(cfg.c_dry_run))
		return 0;

	if (vf->ops)
		return vf->ops->ftruncate(vf, length);

	ret = fstat(vf->fd, &st);
	if (ret) {
		erofs_err("failed to fstat: %s", strerror(errno));
		return -errno;
	}
	length += vf->offset;
	if (S_ISBLK(st.st_mode) || st.st_size == length)
		return 0;
	return ftruncate(vf->fd, length);
}

ssize_t erofs_io_pread(struct erofs_vfile *vf, void *buf, size_t len, u64 pos)
{
	ssize_t ret, read = 0;

	if (__erofs_unlikely(cfg.c_dry_run))
		return 0;

	if (vf->ops)
		return vf->ops->pread(vf, buf, len, pos);

	pos += vf->offset;
	do {
#ifdef HAVE_PREAD64
		ret = pread64(vf->fd, buf, len, (off64_t)pos);
#else
		ret = pread(vf->fd, buf, len, (off_t)pos);
#endif
		if (ret <= 0) {
			if (!ret)
				break;
			if (errno != EINTR) {
				erofs_err("failed to read: %s", strerror(errno));
				return -errno;
			}
			ret = 0;
		}
		pos += ret;
		buf += ret;
		read += ret;
	} while (read < len);

	return read;
}

static int erofs_get_bdev_size(int fd, u64 *bytes)
{
	errno = ENOTSUP;
#ifdef BLKGETSIZE64
	if (ioctl(fd, BLKGETSIZE64, bytes) >= 0)
		return 0;
#endif

#ifdef BLKGETSIZE
	{
		unsigned long size;
		if (ioctl(fd, BLKGETSIZE, &size) >= 0) {
			*bytes = ((u64)size << 9);
			return 0;
		}
	}
#endif
	return -errno;
}

#if defined(__linux__) && !defined(BLKDISCARD)
#define BLKDISCARD	_IO(0x12, 119)
#endif

static int erofs_bdev_discard(int fd, u64 block, u64 count)
{
#ifdef BLKDISCARD
	u64 range[2] = { block, count };

	return ioctl(fd, BLKDISCARD, &range);
#else
	return -EOPNOTSUPP;
#endif
}

int erofs_dev_open(struct erofs_sb_info *sbi, const char *dev, int flags)
{
	bool ro = (flags & O_ACCMODE) == O_RDONLY;
	bool truncate = flags & O_TRUNC;
	struct stat st;
	int fd, ret;

#if defined(HAVE_SYS_STATFS_H) && defined(HAVE_FSTATFS)
	bool again = false;

repeat:
#endif
	fd = open(dev, (ro ? O_RDONLY : O_RDWR | O_CREAT) | O_BINARY, 0644);
	if (fd < 0) {
		erofs_err("failed to open %s: %s", dev, strerror(errno));
		return -errno;
	}

	if (ro || !truncate)
		goto out;

	ret = fstat(fd, &st);
	if (ret) {
		erofs_err("failed to fstat(%s): %s", dev, strerror(errno));
		close(fd);
		return -errno;
	}

	switch (st.st_mode & S_IFMT) {
	case S_IFBLK:
		ret = erofs_get_bdev_size(fd, &sbi->devsz);
		if (ret) {
			erofs_err("failed to get block device size(%s): %s",
				  dev, strerror(errno));
			close(fd);
			return ret;
		}
		sbi->devsz = round_down(sbi->devsz, erofs_blksiz(sbi));
		ret = erofs_bdev_discard(fd, 0, sbi->devsz);
		if (ret)
			erofs_err("failed to erase block device(%s): %s",
				  dev, erofs_strerror(ret));
		break;
	case S_IFREG:
		if (st.st_size) {
#if defined(HAVE_SYS_STATFS_H) && defined(HAVE_FSTATFS)
			struct statfs stfs;

			if (again) {
				close(fd);
				return -ENOTEMPTY;
			}

			/*
			 * fses like EXT4 and BTRFS will flush dirty blocks
			 * after truncate(0) even after the writeback happens
			 * (see kernel commit 7d8f9f7d150d and ccd2506bd431),
			 * which is NOT our intention.  Let's work around this.
			 */
			if (!fstatfs(fd, &stfs) && (stfs.f_type == 0xEF53 ||
					stfs.f_type == 0x9123683E)) {
				close(fd);
				unlink(dev);
				again = true;
				goto repeat;
			}
#endif
			ret = ftruncate(fd, 0);
			if (ret) {
				erofs_err("failed to ftruncate(%s).", dev);
				close(fd);
				return -errno;
			}
		}
		sbi->devblksz = st.st_blksize;
		break;
	default:
		erofs_err("bad file type (%s, %o).", dev, st.st_mode);
		close(fd);
		return -EINVAL;
	}

out:
	sbi->devname = strdup(dev);
	if (!sbi->devname) {
		close(fd);
		return -ENOMEM;
	}
	sbi->bdev.fd = fd;
	erofs_info("successfully to open %s", dev);
	return 0;
}

void erofs_dev_close(struct erofs_sb_info *sbi)
{
	erofs_io_close(&sbi->bdev);
	free(sbi->devname);
	sbi->devname = NULL;
	sbi->bdev.fd = -1;
}

void erofs_blob_closeall(struct erofs_sb_info *sbi)
{
	unsigned int i;

	for (i = 0; i < sbi->nblobs; ++i)
		close(sbi->blobfd[i]);
	sbi->nblobs = 0;
}

int erofs_blob_open_ro(struct erofs_sb_info *sbi, const char *dev)
{
	int fd = open(dev, O_RDONLY | O_BINARY);

	if (fd < 0) {
		erofs_err("failed to open(%s).", dev);
		return -errno;
	}

	sbi->blobfd[sbi->nblobs] = fd;
	erofs_info("successfully to open blob%u %s", sbi->nblobs, dev);
	++sbi->nblobs;
	return 0;
}

ssize_t erofs_dev_read(struct erofs_sb_info *sbi, int device_id,
		       void *buf, u64 offset, size_t len)
{
	ssize_t read;

	if (device_id) {
		if (device_id > sbi->nblobs) {
			erofs_err("invalid device id %d", device_id);
			return -EIO;
		}
		read = erofs_io_pread(&((struct erofs_vfile) {
				.fd = sbi->blobfd[device_id - 1],
			}), buf, len, offset);
	} else {
		read = erofs_io_pread(&sbi->bdev, buf, len, offset);
	}

	if (read < 0)
		return read;
	if (read < len) {
		erofs_info("reach EOF of device @ %llu, pading with zeroes",
			   offset | 0ULL);
		memset(buf + read, 0, len - read);
	}
	return 0;
}

static ssize_t __erofs_copy_file_range(int fd_in, u64 *off_in,
				       int fd_out, u64 *off_out,
				       size_t length)
{
	size_t copied = 0;
	char buf[8192];

	/*
	 * Main copying loop.  The buffer size is arbitrary and is a
	 * trade-off between stack size consumption, cache usage, and
	 * amortization of system call overhead.
	 */
	while (length > 0) {
		size_t to_read;
		ssize_t read_count;
		char *end, *p;

		to_read = min_t(size_t, length, sizeof(buf));
#ifdef HAVE_PREAD64
		read_count = pread64(fd_in, buf, to_read, *off_in);
#else
		read_count = pread(fd_in, buf, to_read, *off_in);
#endif
		if (read_count == 0)
			/* End of file reached prematurely. */
			return copied;
		if (read_count < 0) {
			/* Report the number of bytes copied so far. */
			if (copied > 0)
				return copied;
			return -1;
		}
		*off_in += read_count;

		/* Write the buffer part which was read to the destination. */
		end = buf + read_count;
		for (p = buf; p < end; ) {
			ssize_t write_count;

#ifdef HAVE_PWRITE64
			write_count = pwrite64(fd_out, p, end - p, *off_out);
#else
			write_count = pwrite(fd_out, p, end - p, *off_out);
#endif
			if (write_count < 0) {
				/*
				 * Adjust the input read position to match what
				 * we have written, so that the caller can pick
				 * up after the error.
				 */
				size_t written = p - buf;
				/*
				 * NB: This needs to be signed so that we can
				 * form the negative value below.
				 */
				ssize_t overread = read_count - written;

				*off_in -= overread;
				/* Report the number of bytes copied so far. */
				if (copied + written > 0)
					return copied + written;
				return -1;
			}
			p += write_count;
			*off_out += write_count;
		} /* Write loop.  */
		copied += read_count;
		length -= read_count;
	}
	return copied;
}

ssize_t erofs_copy_file_range(int fd_in, u64 *off_in, int fd_out, u64 *off_out,
			      size_t length)
{
#ifdef HAVE_COPY_FILE_RANGE
	off64_t off64_in = *off_in, off64_out = *off_out;
	ssize_t ret;

	ret = copy_file_range(fd_in, &off64_in, fd_out, &off64_out,
			      length, 0);
	if (ret >= 0)
		goto out;
	if (errno != ENOSYS && errno != EXDEV) {
		ret = -errno;
out:
		*off_in = off64_in;
		*off_out = off64_out;
		return ret;
	}
#endif
	return __erofs_copy_file_range(fd_in, off_in, fd_out, off_out, length);
}

ssize_t erofs_io_read(struct erofs_vfile *vf, void *buf, size_t bytes)
{
	ssize_t i = 0;

	if (vf->ops)
		return vf->ops->read(vf, buf, bytes);

	while (bytes) {
		int len = bytes > INT_MAX ? INT_MAX : bytes;
		int ret;

		ret = read(vf->fd, buf + i, len);
		if (ret < 1) {
			if (ret == 0) {
				break;
			} else if (errno != EINTR) {
				erofs_err("failed to read : %s",
					  strerror(errno));
				return -errno;
			}
		}
		bytes -= ret;
		i += ret;
        }
        return i;
}

ssize_t erofs_io_write(struct erofs_vfile *vf, void *buf, size_t len)
{
	if (vf->ops)
		return vf->ops->write(vf, buf, len);
	return __erofs_io_write(vf->fd, buf, len);
}

#ifdef HAVE_SYS_SENDFILE_H
#include <sys/sendfile.h>
#endif

off_t erofs_io_lseek(struct erofs_vfile *vf, u64 offset, int whence)
{
	if (vf->ops)
		return vf->ops->lseek(vf, offset, whence);

	return lseek(vf->fd, offset, whence);
}

ssize_t erofs_io_sendfile(struct erofs_vfile *vout, struct erofs_vfile *vin,
			  off_t *pos, size_t count)
{
	ssize_t read, written;

	if (vin->ops || vout->ops) {
		if (vin->ops)
			return vin->ops->sendfile(vout, vin, pos, count);
		return vout->ops->sendfile(vout, vin, pos, count);
	}
#if defined(HAVE_SYS_SENDFILE_H) && defined(HAVE_SENDFILE)
	do {
		written = sendfile(vout->fd, vin->fd, pos, count);
		if (written <= 0) {
			if (written < 0) {
				written = -errno;
				if (written == -EOVERFLOW && pos)
					written = 0;
			}
			break;
		}
		count -= written;
	} while (written);
#endif
	while (count) {
		char buf[EROFS_MAX_BLOCK_SIZE];

		read = min_t(u64, count, sizeof(buf));
		if (pos)
			read = erofs_io_pread(vin, buf, read, *pos);
		else
			read = erofs_io_read(vin, buf, read);
		if (read <= 0) {
			written = read;
			break;
		}
		count -= read;
		if (pos)
			*pos += read;
		do {
			written = erofs_io_write(vout, buf, read);
			if (written < 0)
				break;
			read -= written;
		} while (read);
	}
	return written < 0 ? written : count;
}

int erofs_io_xcopy(struct erofs_vfile *vout, off_t pos,
		   struct erofs_vfile *vin, unsigned int len, bool noseek)
{
	if (vout->ops)
		return vout->ops->xcopy(vout, pos, vin, len, noseek);

	if (len && !vin->ops) {
		off_t ret __maybe_unused;

#ifdef HAVE_COPY_FILE_RANGE
		ret = copy_file_range(vin->fd, NULL, vout->fd, &pos, len, 0);
		if (ret > 0)
			len -= ret;
#endif
#if defined(HAVE_SYS_SENDFILE_H) && defined(HAVE_SENDFILE)
		if (len && !noseek) {
			ret = lseek(vout->fd, pos, SEEK_SET);
			if (ret == pos) {
				ret = sendfile(vout->fd, vin->fd, NULL, len);
				if (ret > 0) {
					pos += ret;
					len -= ret;
				}
			}
		}
#endif
	}

	do {
		char buf[32768];
		int ret = min_t(unsigned int, len, sizeof(buf));

		ret = erofs_io_read(vin, buf, ret);
		if (ret < 0)
			return ret;
		if (ret > 0) {
			ret = erofs_io_pwrite(vout, buf, pos, ret);
			if (ret < 0)
				return ret;
			pos += ret;
		}
		len -= ret;
	} while (len);
	return 0;
}

void erofs_io_close(struct erofs_vfile *vf)
{
	if (vf->ops) {
		vf->ops->close(vf);
		return;
	}
	close(vf->fd);
	vf->fd = -1;
}
