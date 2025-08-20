// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Created by Li Guifu <blucerlee@gmail.com>
 */
#include <string.h>
#include <stdlib.h>
#include "erofs/print.h"
#include "erofs/xattr.h"
#include "liberofs_cache.h"

static bool check_layout_compatibility(struct erofs_sb_info *sbi,
				       struct erofs_super_block *dsb)
{
	const unsigned int feature = le32_to_cpu(dsb->feature_incompat);

	sbi->feature_incompat = feature;

	/* check if current kernel meets all mandatory requirements */
	if (feature & ~EROFS_ALL_FEATURE_INCOMPAT) {
		erofs_err("unidentified incompatible feature %x, please upgrade kernel version",
			  feature & ~EROFS_ALL_FEATURE_INCOMPAT);
		return false;
	}
	return true;
}

static int erofs_init_devices(struct erofs_sb_info *sbi,
			      struct erofs_super_block *dsb)
{
	unsigned int ondisk_extradevs, i;
	erofs_off_t pos;

	sbi->total_blocks = sbi->primarydevice_blocks;

	if (!erofs_sb_has_device_table(sbi))
		ondisk_extradevs = 0;
	else
		ondisk_extradevs = le16_to_cpu(dsb->extra_devices);

	if (sbi->extra_devices &&
	    ondisk_extradevs != sbi->extra_devices) {
		erofs_err("extra devices don't match (ondisk %u, given %u)",
			  ondisk_extradevs, sbi->extra_devices);
		return -EINVAL;
	}
	if (!ondisk_extradevs)
		return 0;

	sbi->extra_devices = ondisk_extradevs;
	sbi->device_id_mask = roundup_pow_of_two(ondisk_extradevs + 1) - 1;
	sbi->devs = calloc(ondisk_extradevs, sizeof(*sbi->devs));
	if (!sbi->devs)
		return -ENOMEM;
	pos = le16_to_cpu(dsb->devt_slotoff) * EROFS_DEVT_SLOT_SIZE;
	for (i = 0; i < ondisk_extradevs; ++i) {
		struct erofs_deviceslot dis;
		int ret;

		ret = erofs_dev_read(sbi, 0, &dis, pos, sizeof(dis));
		if (ret < 0) {
			free(sbi->devs);
			sbi->devs = NULL;
			return ret;
		}

		sbi->devs[i].uniaddr = le32_to_cpu(dis.uniaddr_lo);
		sbi->devs[i].blocks = le32_to_cpu(dis.blocks_lo);
		memcpy(sbi->devs[i].tag, dis.tag, sizeof(dis.tag));
		sbi->total_blocks += sbi->devs[i].blocks;
		pos += EROFS_DEVT_SLOT_SIZE;
	}
	return 0;
}

int erofs_read_superblock(struct erofs_sb_info *sbi)
{
	u8 data[EROFS_MAX_BLOCK_SIZE];
	struct erofs_super_block *dsb;
	int read, ret;

	read = erofs_io_pread(&sbi->bdev, data, EROFS_MAX_BLOCK_SIZE, 0);
	if (read < EROFS_SUPER_OFFSET + sizeof(*dsb)) {
		ret = read < 0 ? read : -EIO;
		erofs_err("cannot read erofs superblock: %s",
			  erofs_strerror(ret));
		return ret;
	}
	dsb = (struct erofs_super_block *)(data + EROFS_SUPER_OFFSET);

	ret = -EINVAL;
	if (le32_to_cpu(dsb->magic) != EROFS_SUPER_MAGIC_V1) {
		erofs_err("cannot find valid erofs superblock");
		return ret;
	}

	sbi->feature_compat = le32_to_cpu(dsb->feature_compat);

	sbi->blkszbits = dsb->blkszbits;
	if (sbi->blkszbits < 9 ||
	    sbi->blkszbits > ilog2(EROFS_MAX_BLOCK_SIZE)) {
		erofs_err("blksize %llu isn't supported on this platform",
			  erofs_blksiz(sbi) | 0ULL);
		return ret;
	} else if (!check_layout_compatibility(sbi, dsb)) {
		return ret;
	}

	sbi->sb_size = 128 + dsb->sb_extslots * EROFS_SB_EXTSLOT_SIZE;
	if (sbi->sb_size > read - EROFS_SUPER_OFFSET) {
		erofs_err("invalid sb_extslots %u", dsb->sb_extslots);
		return -EINVAL;
	}
	sbi->primarydevice_blocks = le32_to_cpu(dsb->blocks_lo);
	sbi->meta_blkaddr = le32_to_cpu(dsb->meta_blkaddr);
	sbi->xattr_blkaddr = le32_to_cpu(dsb->xattr_blkaddr);
	sbi->xattr_prefix_start = le32_to_cpu(dsb->xattr_prefix_start);
	sbi->xattr_prefix_count = dsb->xattr_prefix_count;
	if (erofs_sb_has_48bit(sbi) && dsb->rootnid_8b) {
		sbi->root_nid = le64_to_cpu(dsb->rootnid_8b);
		sbi->primarydevice_blocks = (sbi->primarydevice_blocks << 32) |
				le16_to_cpu(dsb->rb.blocks_hi);
	} else {
		sbi->root_nid = le16_to_cpu(dsb->rb.rootnid_2b);
	}
	sbi->packed_nid = le64_to_cpu(dsb->packed_nid);
	if (erofs_sb_has_metabox(sbi)) {
		if (sbi->sb_size <= offsetof(struct erofs_super_block,
					     metabox_nid))
			return -EFSCORRUPTED;
		sbi->metabox_nid = le64_to_cpu(dsb->metabox_nid);
	}
	sbi->inos = le64_to_cpu(dsb->inos);
	sbi->checksum = le32_to_cpu(dsb->checksum);

	sbi->epoch = (s64)le64_to_cpu(dsb->epoch);
	sbi->fixed_nsec = le32_to_cpu(dsb->fixed_nsec);
	sbi->build_time = le32_to_cpu(dsb->build_time);

	memcpy(&sbi->uuid, dsb->uuid, sizeof(dsb->uuid));

	ret = z_erofs_parse_cfgs(sbi, dsb);
	if (ret)
		return ret;

	ret = erofs_init_devices(sbi, dsb);
	if (ret)
		return ret;

	ret = erofs_xattr_prefixes_init(sbi);
	if (ret && sbi->devs) {
		free(sbi->devs);
		sbi->devs = NULL;
	}
	return ret;
}

void erofs_put_super(struct erofs_sb_info *sbi)
{
	if (sbi->devs) {
		int i;

		DBG_BUGON(!sbi->extra_devices);
		for (i = 0; i < sbi->extra_devices; ++i)
			free(sbi->devs[i].src_path);
		free(sbi->devs);
		sbi->devs = NULL;
	}
	erofs_xattr_prefixes_cleanup(sbi);
	if (sbi->bmgr) {
		erofs_buffer_exit(sbi->bmgr);
		sbi->bmgr = NULL;
	}
}

int erofs_writesb(struct erofs_sb_info *sbi)
{
	struct erofs_buffer_head *sb_bh = sbi->bh_sb;
	struct erofs_super_block sb = {
		.magic     = cpu_to_le32(EROFS_SUPER_MAGIC_V1),
		.blkszbits = sbi->blkszbits,
		.rb.rootnid_2b  = cpu_to_le16(sbi->root_nid),
		.inos      = cpu_to_le64(sbi->inos),
		.epoch     = cpu_to_le64(sbi->epoch),
		.build_time = cpu_to_le64(sbi->build_time),
		.fixed_nsec = cpu_to_le32(sbi->fixed_nsec),
		.meta_blkaddr  = cpu_to_le32(sbi->meta_blkaddr),
		.xattr_blkaddr = cpu_to_le32(sbi->xattr_blkaddr),
		.xattr_prefix_count = sbi->xattr_prefix_count,
		.xattr_prefix_start = cpu_to_le32(sbi->xattr_prefix_start),
		.feature_incompat = cpu_to_le32(sbi->feature_incompat),
		.feature_compat = cpu_to_le32(sbi->feature_compat &
					      ~EROFS_FEATURE_COMPAT_SB_CHKSUM),
		.extra_devices = cpu_to_le16(sbi->extra_devices),
		.devt_slotoff = cpu_to_le16(sbi->devt_slotoff),
		.packed_nid = cpu_to_le64(sbi->packed_nid),
	};
	char *buf;
	int ret;

	sb.blocks_lo	= cpu_to_le32(sbi->primarydevice_blocks);
	if (sbi->primarydevice_blocks > UINT32_MAX ||
	    sbi->root_nid > UINT16_MAX) {
		sb.rb.blocks_hi = cpu_to_le16(sbi->primarydevice_blocks >> 32);
		sb.rootnid_8b = cpu_to_le64(sbi->root_nid);
	}
	memcpy(sb.uuid, sbi->uuid, sizeof(sb.uuid));
	memcpy(sb.volume_name, sbi->volume_name, sizeof(sb.volume_name));

	if (erofs_sb_has_compr_cfgs(sbi))
		sb.u1.available_compr_algs = cpu_to_le16(sbi->available_compr_algs);
	else
		sb.u1.lz4_max_distance = cpu_to_le16(sbi->lz4.max_distance);

	if (erofs_sb_has_metabox(sbi))
		sb.metabox_nid = cpu_to_le64(sbi->metabox_nid);
	sb.sb_extslots = (sbi->sb_size - 128) >> 4;

	buf = calloc(round_up(EROFS_SUPER_OFFSET + sbi->sb_size,
			      erofs_blksiz(sbi)), 1);
	if (!buf) {
		erofs_err("failed to allocate memory for sb: %s",
			  erofs_strerror(-errno));
		return -ENOMEM;
	}
	memcpy(buf + EROFS_SUPER_OFFSET, &sb, sbi->sb_size);

	ret = erofs_dev_write(sbi, buf, sb_bh ? erofs_btell(sb_bh, false) : 0,
			      EROFS_SUPER_OFFSET + sbi->sb_size);
	free(buf);
	if (sb_bh)
		erofs_bdrop(sb_bh, false);
	return ret;
}

struct erofs_buffer_head *erofs_reserve_sb(struct erofs_bufmgr *bmgr)
{
	struct erofs_sb_info *sbi = bmgr->sbi;
	struct erofs_buffer_head *bh;
	unsigned int sb_size = 128;
	int err;

	if (erofs_sb_has_metabox(sbi) &&
	    sb_size <= offsetof(struct erofs_super_block, metabox_nid))
		sb_size = offsetof(struct erofs_super_block, metabox_nid) + 8;
	sbi->sb_size = round_up(sb_size, 16);

	bh = erofs_balloc(bmgr, META, 0, 0);
	if (IS_ERR(bh)) {
		erofs_err("failed to allocate super: %s",
			  erofs_strerror(PTR_ERR(bh)));
		return bh;
	}
	bh->op = &erofs_skip_write_bhops;
	err = erofs_bh_balloon(bh, EROFS_SUPER_OFFSET + sbi->sb_size);
	if (err < 0) {
		erofs_err("failed to balloon super: %s", erofs_strerror(err));
		goto err_bdrop;
	}

	/* make sure that the super block should be the very first blocks */
	(void)erofs_mapbh(NULL, bh->block);
	if (erofs_btell(bh, false) != 0) {
		erofs_err("failed to pin super block @ 0");
		err = -EFAULT;
		goto err_bdrop;
	}
	return bh;
err_bdrop:
	erofs_bdrop(bh, true);
	return ERR_PTR(err);
}

int erofs_enable_sb_chksum(struct erofs_sb_info *sbi, u32 *crc)
{
	int ret;
	u8 buf[EROFS_MAX_BLOCK_SIZE];
	unsigned int len;
	struct erofs_super_block *sb;

	/*
	 * skip the first 1024 bytes, to allow for the installation
	 * of x86 boot sectors and other oddities.
	 */
	if (erofs_blksiz(sbi) > EROFS_SUPER_OFFSET)
		len = erofs_blksiz(sbi) - EROFS_SUPER_OFFSET;
	else
		len = erofs_blksiz(sbi);
	ret = erofs_dev_read(sbi, 0, buf, EROFS_SUPER_OFFSET, len);
	if (ret) {
		erofs_err("failed to read superblock to set checksum: %s",
			  erofs_strerror(ret));
		return ret;
	}

	sb = (struct erofs_super_block *)buf;
	if (le32_to_cpu(sb->magic) != EROFS_SUPER_MAGIC_V1) {
		erofs_err("internal error: not an erofs valid image");
		return -EFAULT;
	}

	/* turn on checksum feature */
	sb->feature_compat = cpu_to_le32(le32_to_cpu(sb->feature_compat) |
					 EROFS_FEATURE_COMPAT_SB_CHKSUM);
	*crc = erofs_crc32c(~0, (u8 *)sb, len);

	/* set up checksum field to erofs_super_block */
	sb->checksum = cpu_to_le32(*crc);

	ret = erofs_dev_write(sbi, buf, EROFS_SUPER_OFFSET, len);
	if (ret) {
		erofs_err("failed to write checksummed superblock: %s",
			  erofs_strerror(ret));
		return ret;
	}
	return 0;
}

int erofs_superblock_csum_verify(struct erofs_sb_info *sbi)
{
	u32 len = erofs_blksiz(sbi), crc;
	u8 buf[EROFS_MAX_BLOCK_SIZE];
	struct erofs_super_block *sb;
	int ret;

	if (len > EROFS_SUPER_OFFSET)
		len -= EROFS_SUPER_OFFSET;
	ret = erofs_dev_read(sbi, 0, buf, EROFS_SUPER_OFFSET, len);
	if (ret) {
		erofs_err("failed to read superblock to calculate sbcsum: %d",
			  ret);
		return -1;
	}

	sb = (struct erofs_super_block *)buf;
	sb->checksum = 0;

	crc = erofs_crc32c(~0, (u8 *)sb, len);
	if (crc == sbi->checksum)
		return 0;
	erofs_err("invalid checksum 0x%08x, 0x%08x expected",
		  sbi->checksum, crc);
	return -EBADMSG;
}

int erofs_mkfs_init_devices(struct erofs_sb_info *sbi, unsigned int devices)
{
	struct erofs_buffer_head *bh;

	if (!devices)
		return 0;

	sbi->devs = calloc(devices, sizeof(sbi->devs[0]));
	if (!sbi->devs)
		return -ENOMEM;

	bh = erofs_balloc(sbi->bmgr, DEVT,
			  sizeof(struct erofs_deviceslot) * devices, 0);
	if (IS_ERR(bh)) {
		free(sbi->devs);
		sbi->devs = NULL;
		return PTR_ERR(bh);
	}
	erofs_mapbh(NULL, bh->block);
	bh->op = &erofs_skip_write_bhops;
	sbi->bh_devt = bh;
	sbi->devt_slotoff = erofs_btell(bh, false) / EROFS_DEVT_SLOT_SIZE;
	sbi->extra_devices = devices;
	erofs_sb_set_device_table(sbi);
	return 0;
}

int erofs_write_device_table(struct erofs_sb_info *sbi)
{
	erofs_blk_t nblocks = sbi->primarydevice_blocks;
	struct erofs_buffer_head *bh = sbi->bh_devt;
	erofs_off_t pos;
	unsigned int i, ret;

	if (!sbi->extra_devices)
		goto out;
	if (!bh)
		return -EINVAL;

	pos = erofs_btell(bh, false);
	if (pos == EROFS_NULL_ADDR) {
		DBG_BUGON(1);
		return -EINVAL;
	}

	i = 0;
	do {
		struct erofs_deviceslot dis = {
			.uniaddr_lo = cpu_to_le32(nblocks),
			.blocks_lo = cpu_to_le32(sbi->devs[i].blocks),
		};

		memcpy(dis.tag, sbi->devs[i].tag, sizeof(dis.tag));
		ret = erofs_dev_write(sbi, &dis, pos, sizeof(dis));
		if (ret)
			return ret;
		pos += sizeof(dis);
		nblocks += sbi->devs[i].blocks;
	} while (++i < sbi->extra_devices);

	bh->op = &erofs_drop_directly_bhops;
	erofs_bdrop(bh, false);
	sbi->bh_devt = NULL;
out:
	sbi->total_blocks = nblocks;
	return 0;
}

int erofs_mkfs_format_fs(struct erofs_sb_info *sbi,
			 unsigned int blkszbits, unsigned int dsunit)
{
	struct erofs_buffer_head *bh;
	struct erofs_bufmgr *bmgr;

	sbi->blkszbits = blkszbits;
	bmgr = erofs_buffer_init(sbi, 0, NULL);
	if (!bmgr)
		return -ENOMEM;
	sbi->bmgr = bmgr;
	bmgr->dsunit = dsunit;

	bh = erofs_reserve_sb(bmgr);
	if (IS_ERR(bh))
		return PTR_ERR(bh);
	sbi->bh_sb = bh;
	return 0;
}

int erofs_mkfs_load_fs(struct erofs_sb_info *sbi, unsigned int dsunit)
{
	union {
		struct stat st;
		erofs_blk_t startblk;
	} u;
	struct erofs_bufmgr *bmgr;
	int err;

	sbi->bh_sb = NULL;
	erofs_warn("EXPERIMENTAL incremental build in use. Use at your own risk!");
	err = erofs_read_superblock(sbi);
	if (err) {
		erofs_err("failed to read superblock of %s: %s", sbi->devname,
			  erofs_strerror(err));
		return err;
	}

	err = erofs_io_fstat(&sbi->bdev, &u.st);
	if (!err && S_ISREG(u.st.st_mode))
		u.startblk = DIV_ROUND_UP(u.st.st_size, erofs_blksiz(sbi));
	else
		u.startblk = sbi->primarydevice_blocks;

	bmgr = erofs_buffer_init(sbi, u.startblk, NULL);
	if (!bmgr)
		return -ENOMEM;
	sbi->bmgr = bmgr;
	bmgr->dsunit = dsunit;
	return 0;
}
