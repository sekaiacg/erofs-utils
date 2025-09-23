// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2023, Alibaba Cloud
 * Copyright (C) 2023, Gao Xiang <xiang@kernel.org>
 */
#include "erofs/internal.h"
#include "erofs/print.h"
#include "erofs/config.h"
#include "compressor.h"
#include "erofs/atomic.h"

void *kite_deflate_init(int level, unsigned int dict_size);
void kite_deflate_end(void *s);
int kite_deflate_destsize(void *s, const u8 *in, u8 *out,
			  unsigned int *srcsize, unsigned int target_dstsize);

static int deflate_compress_destsize(const struct erofs_compress *c,
				     const void *src, unsigned int *srcsize,
				     void *dst, unsigned int dstsize)
{
	int rc = kite_deflate_destsize(c->private_data, src, dst,
				       srcsize, dstsize);

	if (rc <= 0)
		return -EFAULT;
	return rc;
}

static int compressor_deflate_exit(struct erofs_compress *c)
{
	if (!c->private_data)
		return -EINVAL;

	kite_deflate_end(c->private_data);
	return 0;
}

static int compressor_deflate_init(struct erofs_compress *c)
{
	static erofs_atomic_bool_t __warnonce;

	if (c->private_data) {
		kite_deflate_end(c->private_data);
		c->private_data = NULL;
	}
	c->private_data = kite_deflate_init(c->compression_level, c->dict_size);
	if (IS_ERR_VALUE(c->private_data))
		return PTR_ERR(c->private_data);

	if (!erofs_atomic_test_and_set(&__warnonce)) {
		erofs_warn("EXPERIMENTAL DEFLATE algorithm in use. Use at your own risk!");
		erofs_warn("*Carefully* check filesystem data correctness to avoid corruption!");
		erofs_warn("Please send a report to <linux-erofs@lists.ozlabs.org> if something is wrong.");
	}
	return 0;
}

static int erofs_compressor_deflate_setlevel(struct erofs_compress *c,
					     int compression_level)
{
	if (compression_level < 0)
		compression_level = erofs_compressor_deflate.default_level;

	if (compression_level > erofs_compressor_deflate.best_level) {
		erofs_err("invalid compression level %d", compression_level);
		return -EINVAL;
	}
	c->compression_level = compression_level;
	return 0;
}

static int erofs_compressor_deflate_setdictsize(struct erofs_compress *c,
						u32 dict_size,
						u32 pclustersize_max)
{
	if (!dict_size)
		dict_size = erofs_compressor_deflate.default_dictsize;

	if (dict_size > erofs_compressor_deflate.max_dictsize) {
		erofs_err("dictionary size %u is too large", dict_size);
		return -EINVAL;
	}
	c->dict_size = dict_size;
	return 0;
}

const struct erofs_compressor erofs_compressor_deflate = {
	.default_level = 1,
	.best_level = 9,
	.default_dictsize = 1 << 15,
	.max_dictsize = 1 << 15,
	.init = compressor_deflate_init,
	.exit = compressor_deflate_exit,
	.setlevel = erofs_compressor_deflate_setlevel,
	.setdictsize = erofs_compressor_deflate_setdictsize,
	.compress_destsize = deflate_compress_destsize,
};
