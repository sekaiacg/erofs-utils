// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C), 2021, Coolpad Group Limited.
 * Created by Yue Hu <huyue2@yulong.com>
 */
#include <stdio.h>
#include <sys/stat.h>
#include "erofs/block_list.h"

#define EROFS_MODNAME	"erofs block_list"
#include "erofs/print.h"

static FILE *block_list_fp;
bool srcmap_enabled;

int erofs_blocklist_open(FILE *fp, bool srcmap)
{
	if (!fp)
		return -ENOENT;
	block_list_fp = fp;
	srcmap_enabled = srcmap;
	return 0;
}

FILE *erofs_blocklist_close(void)
{
	FILE *fp = block_list_fp;

	block_list_fp = NULL;
	return fp;
}

/* XXX: really need to be cleaned up */
void tarerofs_blocklist_write(erofs_blk_t blkaddr, erofs_blk_t nblocks,
			      erofs_off_t srcoff, unsigned int zeroedlen)
{
	if (!block_list_fp || !nblocks || !srcmap_enabled)
		return;

	if (zeroedlen)
		fprintf(block_list_fp, "%08llx %8llx %08" PRIx64 " %08u\n",
			blkaddr | 0ULL, nblocks | 0ULL, srcoff, zeroedlen);
	else
		fprintf(block_list_fp, "%08llx %8llx %08" PRIx64 "\n",
			blkaddr | 0ULL, nblocks | 0ULL, srcoff);
}
