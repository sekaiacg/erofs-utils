// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <xiang@kernel.org>
 */
#include "erofs/internal.h"
#include "compressor.h"
#include "erofs/print.h"

static const struct erofs_algorithm erofs_algs[] = {
	{ "lz4",
#if LZ4_ENABLED
		&erofs_compressor_lz4,
#else
		NULL,
#endif
	  Z_EROFS_COMPRESSION_LZ4, false },

#if LZ4HC_ENABLED
	{ "lz4hc", &erofs_compressor_lz4hc,
	  Z_EROFS_COMPRESSION_LZ4, true },
#endif

	{ "lzma",
#if HAVE_LIBLZMA
		&erofs_compressor_lzma,
#else
		NULL,
#endif
	  Z_EROFS_COMPRESSION_LZMA, false },

	{ "deflate", &erofs_compressor_deflate,
	  Z_EROFS_COMPRESSION_DEFLATE, false },

#if HAVE_LIBDEFLATE
	{ "libdeflate", &erofs_compressor_libdeflate,
	  Z_EROFS_COMPRESSION_DEFLATE, true },
#endif

	{ "zstd",
#ifdef HAVE_LIBZSTD
		&erofs_compressor_libzstd,
#else
		NULL,
#endif
	  Z_EROFS_COMPRESSION_ZSTD, false },
};

int z_erofs_get_compress_algorithm_id(const struct erofs_compress *c)
{
	DBG_BUGON(!c->alg);
	return c->alg->id;
}

const char *z_erofs_list_supported_algorithms(int i, unsigned int *mask)
{
	if (i >= ARRAY_SIZE(erofs_algs))
		return NULL;
	if (!erofs_algs[i].optimisor && (*mask & (1 << erofs_algs[i].id))) {
		*mask ^= 1 << erofs_algs[i].id;
		return erofs_algs[i].name;
	}
	return "";
}

const struct erofs_algorithm *z_erofs_list_available_compressors(int *i)
{
	for (;*i < ARRAY_SIZE(erofs_algs); ++*i) {
		if (!erofs_algs[*i].c)
			continue;
		return &erofs_algs[(*i)++];
	}
	return NULL;
}

int erofs_compress_destsize(const struct erofs_compress *c,
			    const void *src, unsigned int *srcsize,
			    void *dst, unsigned int dstsize)
{
	DBG_BUGON(!c->alg);
	if (!c->alg->c->compress_destsize)
		return -EOPNOTSUPP;

	return c->alg->c->compress_destsize(c, src, srcsize, dst, dstsize);
}

int erofs_compress(const struct erofs_compress *c,
		   const void *src, unsigned int srcsize,
		   void *dst, unsigned int dstcapacity)
{
	DBG_BUGON(!c->alg);
	if (!c->alg->c->compress)
		return -EOPNOTSUPP;

	return c->alg->c->compress(c, src, srcsize, dst, dstcapacity);
}

int erofs_compressor_init(struct erofs_sb_info *sbi, struct erofs_compress *c,
			  char *alg_name, int compression_level,
			  u32 dict_size, u32 pclustersize_max)
{
	int ret, i;

	c->sbi = sbi;

	/* should be written in "minimum compression ratio * 100" */
	c->compress_threshold = 100;
	c->compression_level = -1;
	c->dict_size = 0;

	if (!alg_name) {
		c->alg = NULL;
		return 0;
	}

	ret = -EINVAL;
	for (i = 0; i < ARRAY_SIZE(erofs_algs); ++i) {
		if (alg_name && strcmp(alg_name, erofs_algs[i].name))
			continue;

		if (!erofs_algs[i].c)
			continue;

		if (erofs_algs[i].c->setlevel) {
			ret = erofs_algs[i].c->setlevel(c, compression_level);
			if (ret) {
				erofs_err("failed to set compression level %d for %s",
					  compression_level, alg_name);
				return ret;
			}
		} else if (compression_level >= 0) {
			erofs_err("compression level %d is not supported for %s",
				  compression_level, alg_name);
			return -EINVAL;
		}

		if (erofs_algs[i].c->setdictsize) {
			ret = erofs_algs[i].c->setdictsize(c, dict_size,
							   pclustersize_max);
			if (ret) {
				erofs_err("failed to set dict size %u for %s",
					  dict_size, alg_name);
				return ret;
			}
		} else if (dict_size) {
			erofs_err("dict size is not supported for %s",
				  alg_name);
			return -EINVAL;
		}

		ret = erofs_algs[i].c->init(c);
		if (ret)
			return ret;

		if (!ret) {
			c->alg = &erofs_algs[i];
			return 0;
		}
	}
	erofs_err("Cannot find a valid compressor %s", alg_name);
	return ret;
}

int erofs_compressor_exit(struct erofs_compress *c)
{
	if (c->alg && c->alg->c->exit)
		return c->alg->c->exit(c);
	return 0;
}

void erofs_compressor_reset(struct erofs_compress *c)
{
	if (c->alg && c->alg->c->reset)
		c->alg->c->reset(c);
}
