/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2025 Alibaba Cloud
 */
#ifndef __EROFS_LIB_LIBEROFS_NBD_H
#define __EROFS_LIB_LIBEROFS_NBD_H

#include "erofs/defs.h"

#define EROFS_NBD_MAJOR			43	/* Network block device */

/* Supported request types */
enum {
	EROFS_NBD_CMD_READ		= 0,
	EROFS_NBD_CMD_WRITE		= 1,
	EROFS_NBD_CMD_DISC		= 2,
	EROFS_NBD_CMD_FLUSH		= 3,
	EROFS_NBD_CMD_TRIM		= 4,
	/* userspace defines additional extension commands */
	EROFS_NBD_CMD_WRITE_ZEROES	= 6,
};

struct erofs_nbd_request {
	__be32 magic;			/* NBD_REQUEST_MAGIC */
	u32 type;			/* See NBD_CMD_* */
	union {
		__be64 cookie;		/* Opaque identifier for request */
		char   handle[8];	/* older spelling of cookie */
	};
	u64 from;
        u32 len;
} __packed;

/* 30-day timeout for NBD recovery */
#define EROFS_NBD_DEAD_CONN_TIMEOUT	(3600 * 24 * 30)

long erofs_nbd_in_service(int nbdnum);
int erofs_nbd_devscan(void);
int erofs_nbd_connect(int nbdfd, int blkbits, u64 blocks);
int erofs_nbd_do_it(int nbdfd);
int erofs_nbd_get_request(int skfd, struct erofs_nbd_request *rq);
int erofs_nbd_send_reply_header(int skfd, __le64 cookie, int err);
int erofs_nbd_disconnect(int nbdfd);

int erofs_nbd_nl_connect(int *index, int blkbits, u64 blocks,
			 const char *identifier);
int erofs_nbd_nl_reconnect(int index, const char *identifier);
#endif
