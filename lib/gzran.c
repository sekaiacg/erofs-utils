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

struct erofs_gzran_iostream {
	struct erofs_vfile *vin;
	struct erofs_gzran_cutpoint *cp;
	u32 entries;
	u32 span_size;
};

static void erofs_gzran_ios_vfclose(struct erofs_vfile *vf)
{
	struct erofs_gzran_iostream *ios =
		(struct erofs_gzran_iostream *)vf->payload;
	free(ios->cp);
	free(vf);
}

static ssize_t erofs_gzran_ios_vfpread(struct erofs_vfile *vf, void *buf, size_t len, u64 offset)
{
	struct erofs_gzran_iostream *ios =
		(struct erofs_gzran_iostream *)vf->payload;
	struct erofs_gzran_cutpoint *cp = ios->cp;
	u8 src[1 << 14], discard[EROFS_GZRAN_WINSIZE];
	unsigned int bits;
	bool skip = true;
	u64 inpos;
	z_stream strm;
	int ret;

	while (cp < ios->cp + ios->entries - 1 && cp[1].outpos <= offset)
		++cp;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;
	ret = inflateInit2(&strm, -15);		/* raw inflate */
	if (ret != Z_OK)
		return -EFAULT;

	bits = cp->in_bitpos & 7;
	inpos = (cp->in_bitpos >> 3) - (bits ? 1 : 0);
	ret = erofs_io_pread(ios->vin, src, sizeof(src), inpos);
	if (ret < 0)
		return ret;

	if (bits) {
		inflatePrime(&strm, bits, src[0] >> (8 - bits));
		strm.next_in = src + 1;
		strm.avail_in = ret - 1;
	} else {
		strm.next_in = src;
		strm.avail_in = ret;
	}
	inpos += ret;
	(void)inflateSetDictionary(&strm, cp->window, sizeof(cp->window));

	offset -= cp->outpos;
	do {
		/* define where to put uncompressed data, and how much */
		if (!offset && skip) {          /* at offset now */
			strm.avail_out = len;
			strm.next_out = buf;
			skip = false;		/* only do this once */
		} else if (offset > sizeof(discard)) {	/* skip WINSIZE bytes */
			strm.avail_out = sizeof(discard);
			strm.next_out = discard;
			offset -= sizeof(discard);
		} else if (offset) {			/* last skip */
			strm.avail_out = (unsigned int)offset;
			strm.next_out = discard;
			offset = 0;
		}

		/* uncompress until avail_out filled, or end of stream */
		do {
			if (!strm.avail_in) {
				ret = erofs_io_pread(ios->vin, src, sizeof(src),
						     inpos);
				if (ret < 0)
					return ret;
				if (!ret)
					return -EIO;
				inpos += ret;
				strm.avail_in = ret;
				strm.next_in = src;
			}
			ret = inflate(&strm, Z_NO_FLUSH);       /* normal inflate */
			if (ret == Z_NEED_DICT)
				ret = Z_DATA_ERROR;
			if (ret == Z_MEM_ERROR || ret == Z_DATA_ERROR)
				return -EIO;
			if (ret == Z_STREAM_END)
				break;
		} while (strm.avail_out);

		/* if reach end of stream, then don't keep trying to get more */
		if (ret == Z_STREAM_END)
			break;

		/* do until offset reached and requested data read, or stream ends */
	} while (skip);
	return len - strm.avail_out;
}

static struct erofs_vfops erofs_gzran_ios_vfops = {
	.pread = erofs_gzran_ios_vfpread,
	.close = erofs_gzran_ios_vfclose,
};

struct erofs_vfile *erofs_gzran_zinfo_open(struct erofs_vfile *vin,
					   void *zinfo_buf, unsigned int len)
{
	struct aws_soci_zinfo_header *h;
	struct aws_soci_zinfo_ckpt *c;
	struct erofs_vfile *vf;
	struct erofs_gzran_iostream *ios;
	unsigned int v2_size, version;
	int ret, i;

	if (len && len < sizeof(*h))
		return ERR_PTR(-EINVAL);

	vf = malloc(sizeof(*vf) + sizeof(*ios));
	if (!vf)
		return ERR_PTR(-ENOMEM);

	ios = (struct erofs_gzran_iostream *)vf->payload;
	h = zinfo_buf;
	ios->entries = le32_to_cpu(h->have);
	ios->span_size = le32_to_cpu(h->span_size);

	v2_size = sizeof(*c) * ios->entries + sizeof(*h);
	if (!len || v2_size == len) {
		version = 2;
	} else if (v2_size - sizeof(*c) == len) {
		version = 1;
	} else {
		ret = -EOPNOTSUPP;
		goto err_ios;
	}

	ios->cp = malloc(sizeof(*ios->cp) * ios->entries);
	if (!ios->cp) {
		ret = -ENOMEM;
		goto err_ios;
	}

	i = 0;
	if (version == 1) {
		ios->cp[0] = (struct erofs_gzran_cutpoint) {
			.in_bitpos = 10 << 3,
			.outpos = 0,
		};
		i = 1;
	}

	c = (struct aws_soci_zinfo_ckpt *)(h + 1);
	for (; i < ios->entries; ++i, ++c) {
		ios->cp[i].in_bitpos = (le64_to_cpu(c->in) << 3) | c->bits;
		ios->cp[i].outpos = le64_to_cpu(c->out);
		memcpy(ios->cp[i].window, c->window, sizeof(*c->window));
	}
	ios->vin = vin;
	vf->ops = &erofs_gzran_ios_vfops;
	return vf;
err_ios:
	free(vf);
	return ERR_PTR(ret);
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

struct erofs_vfile *erofs_gzran_zinfo_open(struct erofs_vfile *vin,
					   void *zinfo_buf, unsigned int len)
{
	return ERR_PTR(-EOPNOTSUPP);
}
#endif
