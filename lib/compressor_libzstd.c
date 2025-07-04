// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include "erofs/internal.h"
#include "erofs/print.h"
#include "erofs/config.h"
#include <zstd.h>
#include <zstd_errors.h>
#include <stdlib.h>
#include "compressor.h"
#include "erofs/atomic.h"

struct erofs_libzstd_context {
	ZSTD_CCtx *cctx;
	u8 *fitblk_buffer;
	unsigned int fitblk_bufsiz;
};

static int libzstd_compress(const struct erofs_compress *c,
			    const void *src, unsigned int srcsize,
			    void *dst, unsigned int dstcapacity)
{
	struct erofs_libzstd_context *ctx = c->private_data;
	size_t csize;

	csize = ZSTD_compress2(ctx->cctx, dst, dstcapacity, src, srcsize);
	if (ZSTD_isError(csize)) {
		if (ZSTD_getErrorCode(csize) == ZSTD_error_dstSize_tooSmall)
			return -ENOSPC;
		erofs_err("Zstd compress failed: %s", ZSTD_getErrorName(csize));
		return -EFAULT;
	}
	return csize;
}

static int libzstd_compress_destsize(const struct erofs_compress *c,
				     const void *src, unsigned int *srcsize,
				     void *dst, unsigned int dstsize)
{
	struct erofs_libzstd_context *ctx = c->private_data;
	size_t l = 0;		/* largest input that fits so far */
	size_t l_csize = 0;
	size_t r = *srcsize + 1; /* smallest input that doesn't fit so far */
	size_t m;

	if (dstsize + 32 > ctx->fitblk_bufsiz) {
		u8 *buf = realloc(ctx->fitblk_buffer, dstsize + 32);

		if (!buf)
			return -ENOMEM;
		ctx->fitblk_bufsiz = dstsize + 32;
		ctx->fitblk_buffer = buf;
	}

	m = dstsize * 4;
	for (;;) {
		size_t csize;

		m = max(m, l + 1);
		m = min(m, r - 1);

		csize = ZSTD_compress2(ctx->cctx, ctx->fitblk_buffer,
				       dstsize + 32, src, m);
		if (ZSTD_isError(csize)) {
			if (ZSTD_getErrorCode(csize) == ZSTD_error_dstSize_tooSmall)
				goto doesnt_fit;
			return -EFAULT;
		}

		if (csize > 0 && csize <= dstsize) {
			/* Fits */
			memcpy(dst, ctx->fitblk_buffer, csize);
			l = m;
			l_csize = csize;
			if (r <= l + 1 || csize + 1 >= dstsize)
				break;
			/*
			 * Estimate needed input prefix size based on current
			 * compression ratio.
			 */
			m = (dstsize * m) / csize;
		} else {
doesnt_fit:
			/* Doesn't fit */
			r = m;
			if (r <= l + 1)
				break;
			m = (l + r) / 2;
		}
	}
	*srcsize = l;
	return l_csize;
}

static int compressor_libzstd_exit(struct erofs_compress *c)
{
	struct erofs_libzstd_context *ctx = c->private_data;

	if (!ctx)
		return -EINVAL;

	free(ctx->fitblk_buffer);
	ZSTD_freeCCtx(ctx->cctx);
	free(ctx);
	return 0;
}

static int erofs_compressor_libzstd_setlevel(struct erofs_compress *c,
					     int compression_level)
{
	if (compression_level > erofs_compressor_libzstd.best_level) {
		erofs_err("invalid compression level %d", compression_level);
		return -EINVAL;
	}
	c->compression_level = compression_level;
	return 0;
}

static int erofs_compressor_libzstd_setdictsize(struct erofs_compress *c,
						u32 dict_size)
{
	if (!dict_size) {
		if (erofs_compressor_libzstd.default_dictsize) {
			dict_size = erofs_compressor_libzstd.default_dictsize;
		} else {
			dict_size = min_t(u32, Z_EROFS_ZSTD_MAX_DICT_SIZE,
					  cfg.c_mkfs_pclustersize_max << 3);
			dict_size = 1 << ilog2(dict_size);
		}
	}
	if (dict_size != 1 << ilog2(dict_size) ||
	    dict_size > Z_EROFS_ZSTD_MAX_DICT_SIZE) {
		erofs_err("invalid dictionary size %u", dict_size);
		return -EINVAL;
	}
	c->dict_size = dict_size;
	return 0;
}

static int compressor_libzstd_init(struct erofs_compress *c)
{
	struct erofs_libzstd_context *ctx = c->private_data;
	static erofs_atomic_bool_t __warnonce;
	ZSTD_CCtx *cctx;
	size_t errcode;
	int err;

	if (ctx) {
		ZSTD_freeCCtx(ctx->cctx);
		ctx->cctx = NULL;
		c->private_data = NULL;
	} else {
		ctx = calloc(1, sizeof(*ctx));
		if (!ctx)
			return -ENOMEM;
	}
	cctx = ZSTD_createCCtx();
	if (!cctx) {
		err = -ENOMEM;
		goto out_err;
	}

	err = -EINVAL;
	errcode = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, c->compression_level);
	if (ZSTD_isError(errcode)) {
		erofs_err("failed to set compression level: %s",
			  ZSTD_getErrorName(errcode));
		goto out_err;
	}
	errcode = ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, ilog2(c->dict_size));
	if (ZSTD_isError(errcode)) {
		erofs_err("failed to set window log: %s", ZSTD_getErrorName(errcode));
		goto out_err;
	}
	ctx->cctx = cctx;
	c->private_data = ctx;

	if (!erofs_atomic_test_and_set(&__warnonce)) {
		erofs_warn("EXPERIMENTAL libzstd compressor in use. Note that `fitblk` isn't supported by upstream zstd for now.");
		erofs_warn("Therefore it will takes more time in order to get the optimal result.");
		erofs_info("You could clarify further needs in zstd repository <https://github.com/facebook/zstd/issues> for reference too.");
	}
	return 0;
out_err:
	ZSTD_freeCCtx(cctx);
	free(ctx);
	return err;
}

const struct erofs_compressor erofs_compressor_libzstd = {
	.default_level = ZSTD_CLEVEL_DEFAULT,
	.best_level = 22,
	.max_dictsize = Z_EROFS_ZSTD_MAX_DICT_SIZE,
	.init = compressor_libzstd_init,
	.exit = compressor_libzstd_exit,
	.setlevel = erofs_compressor_libzstd_setlevel,
	.setdictsize = erofs_compressor_libzstd_setdictsize,
	.compress = libzstd_compress,
	.compress_destsize = libzstd_compress_destsize,
};
