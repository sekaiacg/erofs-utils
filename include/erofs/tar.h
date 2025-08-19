/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_TAR_H
#define __EROFS_TAR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/stat.h>

#include "internal.h"

struct erofs_pax_header {
	struct stat st;
	struct list_head xattrs;
	bool use_mtime;
	bool use_size;
	bool use_uid;
	bool use_gid;
	char *path, *link;
};

#define EROFS_IOS_DECODER_NONE		0
#define EROFS_IOS_DECODER_GZIP		1
#define EROFS_IOS_DECODER_LIBLZMA	2

struct erofs_iostream_liblzma;

struct erofs_iostream {
	union {
		struct erofs_vfile vf;
		void *handler;
#ifdef HAVE_LIBLZMA
		struct erofs_iostream_liblzma *lzma;
#endif
	};
	u64 sz;
	char *buffer;
	unsigned int head, tail, bufsize;
	int decoder, dumpfd;
	bool feof;
};

struct erofs_tarfile {
	struct erofs_pax_header global;
	struct erofs_iostream ios;
	char *mapfile, *dumpfile;

	u32 dev;
	int fd;
	u64 offset;
	bool index_mode, headeronly_mode, rvsp_mode, aufs;
	bool ddtaridx_mode;
	bool try_no_reorder;
};

struct erofs_importer;

void erofs_iostream_close(struct erofs_iostream *ios);
int erofs_iostream_open(struct erofs_iostream *ios, int fd, int decoder);
int tarerofs_parse_tar(struct erofs_importer *im, struct erofs_tarfile *tar);

#ifdef __cplusplus
}
#endif

#endif
