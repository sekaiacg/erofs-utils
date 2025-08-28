// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2025 Alibaba Cloud
 */
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include "erofs/io.h"
#include "erofs/err.h"
#include "erofs/print.h"
#include "liberofs_nbd.h"

#define NBD_SET_SOCK		_IO( 0xab, 0 )
#define NBD_SET_BLKSIZE		_IO( 0xab, 1 )
#define NBD_DO_IT		_IO( 0xab, 3 )
#define NBD_CLEAR_SOCK		_IO( 0xab, 4 )
#define NBD_SET_SIZE_BLOCKS     _IO( 0xab, 7 )
#define NBD_DISCONNECT		_IO( 0xab, 8 )
#define NBD_SET_TIMEOUT		_IO( 0xab, 9 )
#define NBD_SET_FLAGS		_IO( 0xab, 10)

#define NBD_REQUEST_MAGIC	0x25609513
#define NBD_REPLY_MAGIC		0x67446698

#define NBD_FLAG_READ_ONLY	(1 << 1)	/* device is read-only */

/*
 * This is the reply packet that nbd-server sends back to the client after
 * it has completed an I/O request (or an error occurs).
 */
struct nbd_reply {
	__be32 magic;		/* NBD_REPLY_MAGIC */
	__be32 error;		/* 0 = ok, else error */
	union {
		__be64 cookie;	/* Opaque identifier from request */
		char handle[8];	/* older spelling of cookie */
	};
} __packed;

long erofs_nbd_in_service(int nbdnum)
{
	int fd, err;
	char s[32];

	(void)snprintf(s, sizeof(s), "/sys/block/nbd%d/size", nbdnum);
	fd = open(s, O_RDONLY);
	if (fd < 0)
		return -errno;
	err = read(fd, s, sizeof(s));
	if (err < 0) {
		err = -errno;
		close(fd);
		return err;
	}
	close(fd);
	if (!memcmp(s, "0\n", sizeof("0\n") - 1))
		return -ENOTCONN;

	(void)snprintf(s, sizeof(s), "/sys/block/nbd%d/pid", nbdnum);
	fd = open(s, O_RDONLY);
	if (fd < 0)
		return -errno;
	err = read(fd, s, sizeof(s));
	if (err < 0) {
		err = -errno;
		close(fd);
		return err;
	}
	close(fd);
	return strtol(s, NULL, 10);
}

int erofs_nbd_devscan(void)
{
	DIR *_dir;
	int err;

	_dir = opendir("/sys/block");
	if (!_dir) {
		fprintf(stderr, "failed to opendir /sys/block: %s\n",
			strerror(errno));
		return -errno;
	}

	while (1) {
		struct dirent *dp;
		char path[64];

		/*
		 * set errno to 0 before calling readdir() in order to
		 * distinguish end of stream and from an error.
		 */
		errno = 0;
		dp = readdir(_dir);
		if (!dp) {
			if (errno)
				err = -errno;
			else
				err = -EBUSY;
			break;
		}

		if (strncmp(dp->d_name, "nbd", 3))
			continue;

		/* Skip nbdX with valid `pid` or `backend` */
		err = snprintf(path, sizeof(path), "%s/pid", dp->d_name);
		if (err < 0)
			continue;
		if (!faccessat(dirfd(_dir), path, F_OK, 0))
			continue;
		err = snprintf(path, sizeof(path), "%s/backend", dp->d_name);
		if (err < 0)
			continue;
		if (!faccessat(dirfd(_dir), path, F_OK, 0))
			continue;
		err = atoi(dp->d_name + 3);
		break;
	}
	closedir(_dir);
	return err;
}

int erofs_nbd_connect(int nbdfd, int blkbits, u64 blocks)
{
	int sv[2], err;

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	if (err < 0)
		return -errno;

	err = ioctl(nbdfd, NBD_CLEAR_SOCK, 0);
	if (err < 0)
		goto err_out;

	err = ioctl(nbdfd, NBD_SET_BLKSIZE, 1U << blkbits);
	if (err < 0)
		goto err_out;

	err = ioctl(nbdfd, NBD_SET_SIZE_BLOCKS, blocks);
	if (err < 0)
		goto err_out;

	err = ioctl(nbdfd, NBD_SET_TIMEOUT, 0);
	if (err < 0)
		goto err_out;

	err = ioctl(nbdfd, NBD_SET_FLAGS, NBD_FLAG_READ_ONLY);
	if (err < 0)
		goto err_out;

	err = ioctl(nbdfd, NBD_SET_SOCK, sv[1]);
	if (err < 0)
		goto err_out;
	return sv[0];
err_out:
	close(sv[0]);
	close(sv[1]);
	return err;
}

int erofs_nbd_do_it(int nbdfd)
{
	int err;

	err = ioctl(nbdfd, NBD_DO_IT, 0);
	if (err < 0) {
		if (errno == EPIPE)
			/*
			 * `ioctl(NBD_DO_IT)` normally returns EPIPE when someone has
			 * disconnected the socket via NBD_DISCONNECT.  We do not want
			 * to return 1 in that case.
			*/
			err = 0;
		else
			err = -errno;
	}
	if (err)
		erofs_err("NBD_DO_IT ends with %s", erofs_strerror(err));
	close(nbdfd);
	return err;
}

int erofs_nbd_get_request(int skfd, struct erofs_nbd_request *rq)
{
	struct erofs_vfile vf = { .fd = skfd };
	int err;

	err = erofs_io_read(&vf, rq, sizeof(*rq));
	if (err < sizeof(*rq))
		return -EPIPE;

	if (rq->magic != cpu_to_be32(NBD_REQUEST_MAGIC))
		return -EIO;

	rq->type = be32_to_cpu((__be32)rq->type);
	rq->from = be64_to_cpu((__be64)rq->from);
	rq->len = be32_to_cpu((__be32)rq->len);
	return 0;
}

int erofs_nbd_send_reply_header(int skfd, __le64 cookie, int err)
{
	struct nbd_reply reply = {
		.magic = cpu_to_be32(NBD_REPLY_MAGIC),
		.error = cpu_to_be32(err),
		.cookie = cookie,
	};
	int ret;

	ret = write(skfd, &reply, sizeof(reply));
	if (ret == sizeof(reply))
		return 0;
	return ret < 0 ? -errno : -EIO;
}

int erofs_nbd_disconnect(int nbdfd)
{
	int err, err2;

	err = ioctl(nbdfd, NBD_DISCONNECT);
	err2 = ioctl(nbdfd, NBD_CLEAR_SOCK);
	return err ?: err2;
}
