// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2025 Alibaba Cloud
 */
#include "erofs/list.h"
#include "erofs/err.h"
#include "liberofs_gzran.h"
#include <stdlib.h>
#include <zlib.h>

#ifdef HAVE_ZLIB
struct erofs_gzran_cutpoint {
	u8	window[EROFS_GZRAN_WINSIZE];	/* preceding 32K of uncompressed data */
	u64	outpos;			/* corresponding offset in uncompressed data */
	u64	in_bitpos;		/* bit offset in input file of first full byte */
};

struct erofs_gzran_cutpoint_item {
	struct erofs_gzran_cutpoint	cp;
	struct list_head		list;
};

struct erofs_gzran_builder {
	struct list_head items;
	struct erofs_vfile *vf;
	z_stream strm;
	u64 totout, totin;
	u32 entries;
	u32 span_size;
	u8 window[EROFS_GZRAN_WINSIZE];
	u8 src[1 << 14];
	bool initial;
};

struct erofs_gzran_builder *erofs_gzran_builder_init(struct erofs_vfile *vf,
						     u32 span_size)
{
	struct erofs_gzran_builder *gb;
	z_stream *strm;
	int ret;

	gb = malloc(sizeof(*gb));
	if (!gb)
		return ERR_PTR(-ENOMEM);
	strm = &gb->strm;
	/* initialize inflate */
	strm->zalloc = Z_NULL;
	strm->zfree = Z_NULL;
	strm->opaque = Z_NULL;
	strm->avail_in = 0;
	strm->next_in = Z_NULL;
	ret = inflateInit2(strm, 47);	/* automatic zlib or gzip decoding */
	if (ret != Z_OK)
		return ERR_PTR(-EFAULT);
	gb->vf = vf;
	gb->span_size = span_size;
	gb->totout = gb->totin = 0;
	gb->entries = 0;
	gb->initial = true;
	init_list_head(&gb->items);
	return gb;
}

/* return up to 32K of data at once */
int erofs_gzran_builder_read(struct erofs_gzran_builder *gb, char *window)
{
	struct erofs_gzran_cutpoint_item *ci;
	struct erofs_gzran_cutpoint *cp;
	z_stream *strm = &gb->strm;
	struct erofs_vfile *vf = gb->vf;
	int read, ret;
	u64 last;

	strm->avail_out = sizeof(gb->window);
	strm->next_out = gb->window;
	do {
		if (!strm->avail_in) {
			read = erofs_io_read(vf, gb->src, sizeof(gb->src));
			if (read <= 0)
				return read;
			strm->avail_in = read;
			strm->next_in = gb->src;
		}
		gb->totin += strm->avail_in;
		gb->totout += strm->avail_out;

		ret = inflate(strm, Z_BLOCK);	/* return at end of block */
		gb->totin -= strm->avail_in;
		gb->totout -= strm->avail_out;

		if (ret == Z_NEED_DICT)
			ret = Z_DATA_ERROR;
		if (ret == Z_MEM_ERROR || ret == Z_DATA_ERROR)
			return -EIO;
		if (ret == Z_STREAM_END) {
			inflateReset(strm);
			gb->initial = true;
			/* address concatenated gzip streams: e.g. (e)stargz */
			if (strm->avail_out < sizeof(gb->window))
				break;
			continue;
		}
		ci = list_empty(&gb->items) ? NULL :
			list_last_entry(&gb->items,
					struct erofs_gzran_cutpoint_item,
					list);
		last = ci ? ci->cp.outpos : 0;
		if ((strm->data_type & 128) && !(strm->data_type & 64) &&
		    (gb->initial || gb->totout - last > gb->span_size)) {
			ci = malloc(sizeof(*ci));
			if (!ci)
				return -ENOMEM;
			init_list_head(&ci->list);
			cp = &ci->cp;

			cp->in_bitpos = (gb->totin << 3) | (strm->data_type & 7);
			cp->outpos = gb->totout;
			read = sizeof(gb->window) - strm->avail_out;
			if (strm->avail_out)
				memcpy(cp->window, gb->window + read, strm->avail_out);
			if (read)
				memcpy(cp->window + strm->avail_out, gb->window, read);
			list_add_tail(&ci->list, &gb->items);
			gb->entries++;
			gb->initial = false;
		}
	} while (strm->avail_out);

	read = sizeof(gb->window) - strm->avail_out;
	memcpy(window, gb->window, read);
	return read;
}

struct aws_soci_zinfo_header {
	__le32 have;
	__le64 span_size;
} __packed;

struct aws_soci_zinfo_ckpt {
	__le64 in;
	__le64 out;
	__u8 bits;
	u8 window[EROFS_GZRAN_WINSIZE];
} __packed;

/* Generate AWS SOCI-compatible on-disk zinfo version 2 */
int erofs_gzran_builder_export_zinfo(struct erofs_gzran_builder *gb,
				     struct erofs_vfile *zinfo_vf)
{
	union {
		struct aws_soci_zinfo_header h;
		struct aws_soci_zinfo_ckpt c;
	} u;
	struct erofs_gzran_cutpoint_item *ci;
	u64 pos;
	int ret;

	BUILD_BUG_ON(sizeof(u.h) != 12);
	u.h = (struct aws_soci_zinfo_header) {
		.have = cpu_to_le32(gb->entries),
		.span_size = cpu_to_le64(gb->span_size),
	};
	ret = erofs_io_pwrite(zinfo_vf, &u.h, 0, sizeof(u.h));
	if (ret < 0)
		return ret;
	if (ret != sizeof(u.h))
		return -EIO;

	pos = sizeof(u.h);
	list_for_each_entry(ci, &gb->items, list) {
		BUILD_BUG_ON(sizeof(u.c) != 17 + EROFS_GZRAN_WINSIZE);
		u.c.in = cpu_to_le64(ci->cp.in_bitpos >> 3);
		u.c.out = cpu_to_le64(ci->cp.outpos);
		u.c.bits = ci->cp.in_bitpos & 7;
		memcpy(u.c.window, ci->cp.window, EROFS_GZRAN_WINSIZE);

		ret = erofs_io_pwrite(zinfo_vf, &u.c, pos, sizeof(u.c));
		if (ret < 0)
			return ret;
		if (ret != sizeof(u.c))
			return -EIO;
		pos += sizeof(u.c);
	}
	return 0;
}

int erofs_gzran_builder_final(struct erofs_gzran_builder *gb)
{
	struct erofs_gzran_cutpoint_item *ci, *n;
	int ret;

	ret = inflateEnd(&gb->strm);
	if (ret != Z_OK)
		return -EFAULT;
	list_for_each_entry_safe(ci, n, &gb->items, list) {
		list_del(&ci->list);
		free(ci);
		--gb->entries;
	}
	DBG_BUGON(gb->entries);
	free(gb);
	return 0;
}
#else
struct erofs_gzran_builder *erofs_gzran_builder_init(struct erofs_vfile *vf,
						     u32 span_size)
{
	return ERR_PTR(-EOPNOTSUPP);
}
int erofs_gzran_builder_read(struct erofs_gzran_builder *gb, char *window)
{
	return 0;
}
int erofs_gzran_builder_export_zinfo(struct erofs_gzran_builder *gb,
				     struct erofs_vfile *zinfo_vf)
{
	return -EOPNOTSUPP;
}
int erofs_gzran_builder_final(struct erofs_gzran_builder *gb)
{
	return 0;
}
#endif
