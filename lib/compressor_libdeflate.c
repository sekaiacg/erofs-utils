// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include "erofs/internal.h"
#include "erofs/print.h"
#include "erofs/config.h"
#include <libdeflate.h>
#include <stdlib.h>
#include "compressor.h"
#include "erofs/atomic.h"

struct erofs_libdeflate_context {
	struct libdeflate_compressor *strm;
	u8 *fitblk_buffer;
	unsigned int fitblk_bufsiz;
	size_t last_uncompressed_size;
};

static int libdeflate_compress(const struct erofs_compress *c,
			       const void *src, unsigned int srcsize,
			       void *dst, unsigned int dstcapacity)
{
	struct erofs_libdeflate_context *ctx = c->private_data;
	size_t csize;

	csize = libdeflate_deflate_compress(ctx->strm, src, srcsize,
					    dst, dstcapacity);
	if (!csize)
		return -ENOSPC;
	/* See the comment in libdeflate_compress_destsize() */
	if (!((u8 *)dst)[0])
		((u8 *)dst)[0] = 1 << (2 + 1);
	return csize;
}

static int libdeflate_compress_destsize(const struct erofs_compress *c,
				        const void *src, unsigned int *srcsize,
				        void *dst, unsigned int dstsize)
{
	struct erofs_libdeflate_context *ctx = c->private_data;
	size_t l = 0; /* largest input that fits so far */
	size_t l_csize = 0;
	size_t r = *srcsize + 1; /* smallest input that doesn't fit so far */
	size_t m;

	if (dstsize + 9 > ctx->fitblk_bufsiz) {
		u8 *buf = realloc(ctx->fitblk_buffer, dstsize + 9);

		if (!buf)
			return -ENOMEM;
		ctx->fitblk_bufsiz = dstsize + 9;
		ctx->fitblk_buffer = buf;
	}

	if (ctx->last_uncompressed_size)
		m = ctx->last_uncompressed_size * 15 / 16;
	else
		m = dstsize * 4;
	for (;;) {
		size_t csize;

		m = max(m, l + 1);
		m = min(m, r - 1);

		csize = libdeflate_deflate_compress(ctx->strm, src, m,
						    ctx->fitblk_buffer,
						    dstsize + 9);
		/*printf("Tried %zu => %zu\n", m, csize);*/
		if (csize > 0 && csize <= dstsize) {
			/* Fits */
			memcpy(dst, ctx->fitblk_buffer, csize);
			l = m;
			l_csize = csize;
			if (r <= l + 1 || csize +
				(22 - 2*(int)c->compression_level) >= dstsize)
				break;
			/*
			 * Estimate needed input prefix size based on current
			 * compression ratio.
			 */
			m = (dstsize * m) / csize;
		} else {
			/* Doesn't fit */
			r = m;
			if (r <= l + 1)
				break;
			m = (l + r) / 2;
		}
	}

	/*
	 * Since generic EROFS on-disk compressed data will be filled with
	 * leading 0s (but no more than one block, 4KB for example, even the
	 * whole pcluster is 128KB) if not filled, it will be used to identify
	 * the actual compressed length as well without taking more reserved
	 * compressed bytes or some extra metadata to record this.
	 *
	 * DEFLATE streams can also be used in this way, if it starts from a
	 * non-last stored block, flag an unused bit instead to avoid the zero
	 * byte. It's still a valid one according to the DEFLATE specification.
	 */
	if (l_csize && !((u8 *)dst)[0])
	       ((u8 *)dst)[0] = 1 << (2 + 1);

	/*printf("Choosing %zu => %zu\n", l, l_csize);*/
	*srcsize = l;
	ctx->last_uncompressed_size = l;
	return l_csize;
}

static int compressor_libdeflate_exit(struct erofs_compress *c)
{
	struct erofs_libdeflate_context *ctx = c->private_data;

	if (!ctx)
		return -EINVAL;
	libdeflate_free_compressor(ctx->strm);
	free(ctx->fitblk_buffer);
	free(ctx);
	return 0;
}

static int compressor_libdeflate_init(struct erofs_compress *c)
{
	static erofs_atomic_bool_t __warnonce;
	struct erofs_libdeflate_context *ctx;

	DBG_BUGON(c->private_data);
	ctx = calloc(1, sizeof(struct erofs_libdeflate_context));
	if (!ctx)
		return -ENOMEM;
	ctx->strm = libdeflate_alloc_compressor(c->compression_level);
	if (!ctx->strm) {
		free(ctx);
		return -ENOMEM;
	}
	c->private_data = ctx;
	if (!erofs_atomic_test_and_set(&__warnonce))
		erofs_warn("EXPERIMENTAL libdeflate compressor in use. Use at your own risk!");
	return 0;
}

static void compressor_libdeflate_reset(struct erofs_compress *c)
{
	struct erofs_libdeflate_context *ctx = c->private_data;

	ctx->last_uncompressed_size = 0;
}

static int erofs_compressor_libdeflate_setlevel(struct erofs_compress *c,
						int compression_level)
{
	if (compression_level < 0)
		compression_level = erofs_compressor_libdeflate.default_level;

	if (compression_level > erofs_compressor_libdeflate.best_level) {
		erofs_err("invalid compression level %d", compression_level);
		return -EINVAL;
	}
	c->compression_level = compression_level;
	return 0;
}

const struct erofs_compressor erofs_compressor_libdeflate = {
	.default_level = 1,
	.best_level = 12,
	.init = compressor_libdeflate_init,
	.exit = compressor_libdeflate_exit,
	.reset = compressor_libdeflate_reset,
	.setlevel = erofs_compressor_libdeflate_setlevel,
	.compress = libdeflate_compress,
	.compress_destsize = libdeflate_compress_destsize,
};
