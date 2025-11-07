// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include <stdlib.h>
#include "erofs/inode.h"
#include "erofs/importer.h"
#include "erofs/print.h"
#include "liberofs_cache.h"
#include "liberofs_private.h"
#include "liberofs_metabox.h"

const char *erofs_metabox_identifier = "metabox";

struct erofs_metamgr {
	struct erofs_vfile vf;
	struct erofs_bufmgr *bmgr;
};

static void erofs_metamgr_exit(struct erofs_metamgr *m2gr)
{
	DBG_BUGON(!m2gr->bmgr);
	erofs_buffer_exit(m2gr->bmgr);
	erofs_io_close(&m2gr->vf);
	free(m2gr);
}
static int erofs_metamgr_init(struct erofs_sb_info *sbi,
			      struct erofs_metamgr *m2gr)
{
	int ret;

	ret = erofs_tmpfile();
	if (ret < 0)
		return ret;

	m2gr->vf = (struct erofs_vfile){ .fd = ret };
	m2gr->bmgr = erofs_buffer_init(sbi, 0, &m2gr->vf);
	if (!m2gr->bmgr)
		return -ENOMEM;
	return 0;
}

void erofs_metadata_exit(struct erofs_sb_info *sbi)
{
	if (sbi->m2gr) {
		erofs_metamgr_exit(sbi->m2gr);
		sbi->m2gr = NULL;
	}
	if (sbi->mxgr) {
		erofs_metamgr_exit(sbi->mxgr);
		sbi->mxgr = NULL;
	}
}

int erofs_metadata_init(struct erofs_sb_info *sbi)
{
	struct erofs_metamgr *m2gr;
	int ret;

	if (!sbi->m2gr && sbi->meta_blkaddr == EROFS_META_NEW_ADDR) {
		m2gr = malloc(sizeof(*m2gr));
		if (!m2gr)
			return -ENOMEM;
		ret = erofs_metamgr_init(sbi, m2gr);
		if (ret)
			goto err_free;
		sbi->m2gr = m2gr;
	}

	if (!sbi->mxgr && erofs_sb_has_metabox(sbi)) {
		m2gr = malloc(sizeof(*m2gr));
		if (!m2gr)
			return -ENOMEM;
		ret = erofs_metamgr_init(sbi, m2gr);
		if (ret)
			goto err_free;
		sbi->mxgr = m2gr;
	}
	return 0;
err_free:
	free(m2gr);
	return ret;
}

struct erofs_bufmgr *erofs_metadata_bmgr(struct erofs_sb_info *sbi, bool mbox)
{
	if (mbox) {
		if (sbi->mxgr)
			return sbi->mxgr->bmgr;
	} else if (sbi->m2gr) {
		return sbi->m2gr->bmgr;
	}
	return NULL;
}

int erofs_metabox_iflush(struct erofs_importer *im)
{
	struct erofs_sb_info *sbi = im->sbi;
	struct erofs_metamgr *mxgr = sbi->mxgr;
	struct erofs_inode *inode;
	int err;

	if (!mxgr || !erofs_sb_has_metabox(sbi))
		return -EINVAL;

	err = erofs_bflush(mxgr->bmgr, NULL);
	if (err)
		return err;

	if (erofs_io_lseek(&mxgr->vf, 0, SEEK_END) <= 0)
		return 0;
	inode = erofs_mkfs_build_special_from_fd(im, mxgr->vf.fd,
						 EROFS_METABOX_INODE);
	sbi->metabox_nid = erofs_lookupnid(inode);
	erofs_iput(inode);
	return 0;
}

int erofs_metazone_flush(struct erofs_sb_info *sbi)
{
	struct erofs_metamgr *m2gr = sbi->m2gr;
	struct erofs_buffer_head *bh;
	struct erofs_bufmgr *m2bgr;
	erofs_blk_t meta_blkaddr;
	u64 length, pos_out;
	int ret, count;

	if (!m2gr)
		return 0;
	m2bgr = m2gr->bmgr;

	ret = erofs_bflush(m2bgr, NULL);
	if (ret)
		return ret;

	length = erofs_mapbh(m2bgr, NULL) << sbi->blkszbits;
	bh = erofs_balloc(sbi->bmgr, DATA, length, 0);
	if (!bh)
		return PTR_ERR(bh);

	erofs_mapbh(NULL, bh->block);
	pos_out = erofs_btell(bh, false);
	meta_blkaddr = pos_out >> sbi->blkszbits;
	do {
		count = min_t(erofs_off_t, length, INT_MAX);
		ret = erofs_io_xcopy(sbi->bmgr->vf, pos_out,
				     &m2gr->vf, count, false);
		if (ret < 0)
			break;
		pos_out += count;
	} while (length -= count);
	bh->op = &erofs_drop_directly_bhops;
	erofs_bdrop(bh, false);
	sbi->meta_blkaddr += meta_blkaddr;
	return 0;
}
