/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_IO_H
#define __EROFS_IO_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include "defs.h"

#ifndef O_BINARY
#define O_BINARY	0
#endif

struct erofs_vfile;

struct erofs_vfops {
	ssize_t (*pread)(struct erofs_vfile *vf, void *buf, u64 offset, size_t len);
	ssize_t (*pwrite)(struct erofs_vfile *vf, const void *buf, u64 offset, size_t len);
	ssize_t (*pwritev)(struct erofs_vfile *vf, const struct iovec *iov,
			   int iovcnt, u64 pos);
	int (*fsync)(struct erofs_vfile *vf);
	int (*fallocate)(struct erofs_vfile *vf, u64 offset, size_t len, bool pad);
	int (*ftruncate)(struct erofs_vfile *vf, u64 length);
	ssize_t (*read)(struct erofs_vfile *vf, void *buf, size_t len);
	off_t (*lseek)(struct erofs_vfile *vf, u64 offset, int whence);
	int (*fstat)(struct erofs_vfile *vf, struct stat *buf);
	int (*xcopy)(struct erofs_vfile *vout, off_t pos,
		     struct erofs_vfile *vin, unsigned int len, bool noseek);
};

/* don't extend this; instead, use payload for any extra information */
struct erofs_vfile {
	struct erofs_vfops *ops;
	union {
		struct {
			u64 offset;
			int fd;
		};
		u8 payload[16];
	};
};

ssize_t __erofs_io_write(int fd, const void *buf, size_t len);

int erofs_io_fstat(struct erofs_vfile *vf, struct stat *buf);
ssize_t erofs_io_pwrite(struct erofs_vfile *vf, const void *buf, u64 pos, size_t len);
ssize_t erofs_io_pwritev(struct erofs_vfile *vf, const struct iovec *iov,
			 int iovcnt, u64 pos);
int erofs_io_fsync(struct erofs_vfile *vf);
ssize_t erofs_io_fallocate(struct erofs_vfile *vf, u64 offset, size_t len, bool pad);
int erofs_io_ftruncate(struct erofs_vfile *vf, u64 length);
ssize_t erofs_io_pread(struct erofs_vfile *vf, void *buf, u64 offset, size_t len);
ssize_t erofs_io_read(struct erofs_vfile *vf, void *buf, size_t len);
off_t erofs_io_lseek(struct erofs_vfile *vf, u64 offset, int whence);

ssize_t erofs_copy_file_range(int fd_in, u64 *off_in, int fd_out, u64 *off_out,
			      size_t length);
int erofs_io_xcopy(struct erofs_vfile *vout, off_t pos,
		   struct erofs_vfile *vin, unsigned int len, bool noseek);

#ifdef __cplusplus
}
#endif

#endif // EROFS_IO_H_
