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

#ifdef HAVE_NETLINK_GENL_GENL_H
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#endif

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

#if defined(HAVE_NETLINK_GENL_GENL_H) && defined(HAVE_LIBNL_GENL_3)
enum {
	NBD_ATTR_UNSPEC,
	NBD_ATTR_INDEX,
	NBD_ATTR_SIZE_BYTES,
	NBD_ATTR_BLOCK_SIZE_BYTES,
	NBD_ATTR_TIMEOUT,
	NBD_ATTR_SERVER_FLAGS,
	NBD_ATTR_CLIENT_FLAGS,
	NBD_ATTR_SOCKETS,
	NBD_ATTR_DEAD_CONN_TIMEOUT,
	NBD_ATTR_DEVICE_LIST,
	NBD_ATTR_BACKEND_IDENTIFIER,
	__NBD_ATTR_MAX,
};
#define NBD_ATTR_MAX (__NBD_ATTR_MAX - 1)

enum {
	NBD_SOCK_ITEM_UNSPEC,
	NBD_SOCK_ITEM,
	__NBD_SOCK_ITEM_MAX,
};
#define NBD_SOCK_ITEM_MAX (__NBD_SOCK_ITEM_MAX - 1)

enum {
	NBD_SOCK_UNSPEC,
	NBD_SOCK_FD,
	__NBD_SOCK_MAX,
};
#define NBD_SOCK_MAX (__NBD_SOCK_MAX - 1)

enum {
	NBD_CMD_UNSPEC,
	NBD_CMD_CONNECT,
	NBD_CMD_DISCONNECT,
	__NBD_CMD_MAX,
};

/* client behavior specific flags */
/* delete the nbd device on disconnect */
#define NBD_CFLAG_DESTROY_ON_DISCONNECT		(1 << 0)
/* disconnect the nbd device on close by last opener */
#define NBD_CFLAG_DISCONNECT_ON_CLOSE		(1 << 1)

static struct nl_sock *erofs_nbd_get_nl_sock(int *driver_id)
{
	struct nl_sock *socket;
	int err;

	socket = nl_socket_alloc();
	if (!socket) {
		erofs_err("Couldn't allocate netlink socket");
		return ERR_PTR(-ENOMEM);
	}

	err = genl_connect(socket);
	if (err) {
		erofs_err("Couldn't connect to the generic netlink socket");
		return ERR_PTR(err);
	}

	err = genl_ctrl_resolve(socket, "nbd");
	if (err < 0) {
		erofs_err("Failed to resolve NBD netlink family. Ensure the NBD module is loaded and it supports netlink.");
		return ERR_PTR(err);
	}
	*driver_id = err;
	return socket;
}

struct erofs_nbd_nl_cfg_cbctx {
	int *index;
	int errcode;
};

static int erofs_nbd_nl_cfg_cb(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
	struct erofs_nbd_nl_cfg_cbctx *ctx = arg;
	int err;

	err = nla_parse(msg_attr, NBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (err) {
		erofs_err("Invalid response from the kernel");
		ctx->errcode = err;
	}

	if (!msg_attr[NBD_ATTR_INDEX]) {
		erofs_err("Did not receive index from the kernel");
		ctx->errcode = -EBADMSG;
	}
	*ctx->index = nla_get_u32(msg_attr[NBD_ATTR_INDEX]);
	erofs_dbg("Connected /dev/nbd%d\n", *ctx->index);
	ctx->errcode = 0;
	return NL_OK;
}

int erofs_nbd_nl_connect(int *index, int blkbits, u64 blocks,
			 const char *identifier)
{
	struct erofs_nbd_nl_cfg_cbctx cbctx = {
		.index = index,
	};
	struct nlattr *sock_attr = NULL, *sock_opt = NULL;
	struct nl_sock *socket;
	struct nl_msg *msg;
	int sv[2], err;
	int driver_id;

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	if (err < 0)
		return -errno;

	socket = erofs_nbd_get_nl_sock(&driver_id);
	if (IS_ERR(socket)) {
		err = PTR_ERR(socket);
		goto err_out;
	}
	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM,
			    erofs_nbd_nl_cfg_cb, &cbctx);

	msg = nlmsg_alloc();
	if (!msg) {
		erofs_err("Couldn't allocate netlink message");
		err = -ENOMEM;
		goto err_nls_free;
	}

	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
		    NBD_CMD_CONNECT, 0);
	if (*index >= 0)
		NLA_PUT_U32(msg, NBD_ATTR_INDEX, *index);
	NLA_PUT_U64(msg, NBD_ATTR_BLOCK_SIZE_BYTES, 1u << blkbits);
	NLA_PUT_U64(msg, NBD_ATTR_SIZE_BYTES, blocks << blkbits);
	NLA_PUT_U64(msg, NBD_ATTR_SERVER_FLAGS, NBD_FLAG_READ_ONLY);
	NLA_PUT_U64(msg, NBD_ATTR_TIMEOUT, 0);
	if (identifier)
		NLA_PUT_STRING(msg, NBD_ATTR_BACKEND_IDENTIFIER, identifier);

	err = -EINVAL;
	sock_attr = nla_nest_start(msg, NBD_ATTR_SOCKETS);
	if (!sock_attr) {
		erofs_err("Couldn't nest the sockets for our connection");
		goto err_nlm_free;
	}

	sock_opt = nla_nest_start(msg, NBD_SOCK_ITEM);
	if (!sock_opt) {
		nla_nest_cancel(msg, sock_attr);
		goto err_nlm_free;
	}
	NLA_PUT_U32(msg, NBD_SOCK_FD, sv[1]);
	nla_nest_end(msg, sock_opt);
	nla_nest_end(msg, sock_attr);

	err = nl_send_sync(socket, msg);
	if (err)
		goto err_out;
	nl_socket_free(socket);
	if (cbctx.errcode)
		return cbctx.errcode;
	return sv[0];

nla_put_failure:
	if (sock_opt)
		nla_nest_cancel(msg, sock_opt);
	if (sock_attr)
		nla_nest_cancel(msg, sock_attr);
err_nlm_free:
	nlmsg_free(msg);
err_nls_free:
	nl_socket_free(socket);
err_out:
	close(sv[0]);
	close(sv[1]);
	return err;
}
#else
int erofs_nbd_nl_connect(int *index, int blkbits, u64 blocks,
			 const char *identifier)
{
	return -EOPNOTSUPP;
}
#endif

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
