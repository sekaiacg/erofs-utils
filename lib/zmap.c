// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * (a large amount of code was adapted from Linux kernel. )
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Created by Gao Xiang <xiang@kernel.org>
 * Modified by Huang Jianan <huangjianan@oppo.com>
 */
#include "erofs/internal.h"
#include "erofs/print.h"

struct z_erofs_maprecorder {
	struct erofs_inode *inode;
	struct erofs_map_blocks *map;

	unsigned long lcn;
	/* compression extent information gathered */
	u8  type, headtype;
	u16 clusterofs;
	u16 delta[2];
	erofs_blk_t pblk, compressedblks;
	erofs_off_t nextpackoff;
	bool partialref;
};

static int z_erofs_load_full_lcluster(struct z_erofs_maprecorder *m,
				      unsigned long lcn)
{
	struct erofs_inode *const vi = m->inode;
	struct erofs_sb_info *sbi = vi->sbi;
	const erofs_off_t pos = Z_EROFS_FULL_INDEX_START(erofs_iloc(vi) +
			vi->inode_isize + vi->xattr_isize) +
			lcn * sizeof(struct z_erofs_lcluster_index);
	struct z_erofs_lcluster_index *di;
	unsigned int advise;

	di = erofs_read_metabuf(&m->map->buf, sbi, pos,
				erofs_inode_in_metabox(vi));
	if (IS_ERR(di))
		return PTR_ERR(di);
	m->lcn = lcn;
	m->nextpackoff = pos + sizeof(struct z_erofs_lcluster_index);

	advise = le16_to_cpu(di->di_advise);
	m->type = advise & Z_EROFS_LI_LCLUSTER_TYPE_MASK;
	if (m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
		m->clusterofs = 1 << vi->z_lclusterbits;
		m->delta[0] = le16_to_cpu(di->di_u.delta[0]);
		if (m->delta[0] & Z_EROFS_LI_D0_CBLKCNT) {
			if (!(vi->z_advise & (Z_EROFS_ADVISE_BIG_PCLUSTER_1 |
					Z_EROFS_ADVISE_BIG_PCLUSTER_2))) {
				DBG_BUGON(1);
				return -EFSCORRUPTED;
			}
			m->compressedblks = m->delta[0] & ~Z_EROFS_LI_D0_CBLKCNT;
			m->delta[0] = 1;
		}
		m->delta[1] = le16_to_cpu(di->di_u.delta[1]);
	} else {
		m->partialref = !!(advise & Z_EROFS_LI_PARTIAL_REF);
		m->clusterofs = le16_to_cpu(di->di_clusterofs);
		if (m->clusterofs >= 1 << vi->z_lclusterbits) {
			DBG_BUGON(1);
			return -EFSCORRUPTED;
		}
		m->pblk = le32_to_cpu(di->di_u.blkaddr);
	}
	return 0;
}

static unsigned int decode_compactedbits(unsigned int lobits,
					 u8 *in, unsigned int pos, u8 *type)
{
	const unsigned int v = get_unaligned_le32(in + pos / 8) >> (pos & 7);
	const unsigned int lo = v & ((1 << lobits) - 1);

	*type = (v >> lobits) & 3;
	return lo;
}

static int get_compacted_la_distance(unsigned int lobits,
				     unsigned int encodebits,
				     unsigned int vcnt, u8 *in, int i)
{
	unsigned int lo, d1 = 0;
	u8 type;

	DBG_BUGON(i >= vcnt);

	do {
		lo = decode_compactedbits(lobits, in, encodebits * i, &type);

		if (type != Z_EROFS_LCLUSTER_TYPE_NONHEAD)
			return d1;
		++d1;
	} while (++i < vcnt);

	/* vcnt - 1 (Z_EROFS_LCLUSTER_TYPE_NONHEAD) item */
	if (!(lo & Z_EROFS_LI_D0_CBLKCNT))
		d1 += lo - 1;
	return d1;
}

static int z_erofs_load_compact_lcluster(struct z_erofs_maprecorder *m,
					 unsigned long lcn, bool lookahead)
{
	struct erofs_inode *const vi = m->inode;
	struct erofs_sb_info *sbi = vi->sbi;
	const erofs_off_t ebase = sizeof(struct z_erofs_map_header) +
		round_up(erofs_iloc(vi) + vi->inode_isize + vi->xattr_isize, 8);
	const unsigned int lclusterbits = vi->z_lclusterbits;
	const unsigned int totalidx = BLK_ROUND_UP(sbi, vi->i_size);
	unsigned int compacted_4b_initial, compacted_2b, amortizedshift;
	unsigned int vcnt, lo, lobits, encodebits, nblk, bytes;
	bool big_pcluster = vi->z_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1;
	erofs_off_t pos;
	u8 *in, type;
	int i;

	if (lcn >= totalidx || lclusterbits > 14)
		return -EINVAL;

	m->lcn = lcn;
	/* used to align to 32-byte (compacted_2b) alignment */
	compacted_4b_initial = ((32 - ebase % 32) / 4) & 7;
	compacted_2b = 0;
	if ((vi->z_advise & Z_EROFS_ADVISE_COMPACTED_2B) &&
	    compacted_4b_initial < totalidx)
		compacted_2b = rounddown(totalidx - compacted_4b_initial, 16);

	pos = ebase;
	amortizedshift = 2;	/* compact_4b */
	if (lcn >= compacted_4b_initial) {
		pos += compacted_4b_initial * 4;
		lcn -= compacted_4b_initial;
		if (lcn < compacted_2b) {
			amortizedshift = 1;
		} else {
			pos += compacted_2b * 2;
			lcn -= compacted_2b;
		}
	}
	pos += lcn * (1 << amortizedshift);

	/* figure out the lcluster count in this pack */
	if (1 << amortizedshift == 4 && lclusterbits <= 14)
		vcnt = 2;
	else if (1 << amortizedshift == 2 && lclusterbits <= 12)
		vcnt = 16;
	else
		return -EOPNOTSUPP;

	in = erofs_read_metabuf(&m->map->buf, sbi, pos,
				erofs_inode_in_metabox(vi));
	if (IS_ERR(in))
		return PTR_ERR(in);

	/* it doesn't equal to round_up(..) */
	m->nextpackoff = round_down(pos, vcnt << amortizedshift) +
			 (vcnt << amortizedshift);
	lobits = max(lclusterbits, ilog2(Z_EROFS_LI_D0_CBLKCNT) + 1U);
	encodebits = ((vcnt << amortizedshift) - sizeof(__le32)) * 8 / vcnt;
	bytes = pos & ((vcnt << amortizedshift) - 1);
	in -= bytes;
	i = bytes >> amortizedshift;

	lo = decode_compactedbits(lobits, in, encodebits * i, &type);
	m->type = type;
	if (type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
		m->clusterofs = 1 << lclusterbits;

		/* figure out lookahead_distance: delta[1] if needed */
		if (lookahead)
			m->delta[1] = get_compacted_la_distance(lobits,
						encodebits, vcnt, in, i);
		if (lo & Z_EROFS_LI_D0_CBLKCNT) {
			if (!big_pcluster) {
				DBG_BUGON(1);
				return -EFSCORRUPTED;
			}
			m->compressedblks = lo & ~Z_EROFS_LI_D0_CBLKCNT;
			m->delta[0] = 1;
			return 0;
		} else if (i + 1 != (int)vcnt) {
			m->delta[0] = lo;
			return 0;
		}
		/*
		 * since the last lcluster in the pack is special,
		 * of which lo saves delta[1] rather than delta[0].
		 * Hence, get delta[0] by the previous lcluster indirectly.
		 */
		lo = decode_compactedbits(lobits, in,
					  encodebits * (i - 1), &type);
		if (type != Z_EROFS_LCLUSTER_TYPE_NONHEAD)
			lo = 0;
		else if (lo & Z_EROFS_LI_D0_CBLKCNT)
			lo = 1;
		m->delta[0] = lo + 1;
		return 0;
	}
	m->clusterofs = lo;
	m->delta[0] = 0;
	/* figout out blkaddr (pblk) for HEAD lclusters */
	if (!big_pcluster) {
		nblk = 1;
		while (i > 0) {
			--i;
			lo = decode_compactedbits(lobits, in,
						  encodebits * i, &type);
			if (type == Z_EROFS_LCLUSTER_TYPE_NONHEAD)
				i -= lo;

			if (i >= 0)
				++nblk;
		}
	} else {
		nblk = 0;
		while (i > 0) {
			--i;
			lo = decode_compactedbits(lobits, in,
						  encodebits * i, &type);
			if (type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
				if (lo & Z_EROFS_LI_D0_CBLKCNT) {
					--i;
					nblk += lo & ~Z_EROFS_LI_D0_CBLKCNT;
					continue;
				}
				/* bigpcluster shouldn't have plain d0 == 1 */
				if (lo <= 1) {
					DBG_BUGON(1);
					return -EFSCORRUPTED;
				}
				i -= lo - 2;
				continue;
			}
			++nblk;
		}
	}
	in += (vcnt << amortizedshift) - sizeof(__le32);
	m->pblk = le32_to_cpu(*(__le32 *)in) + nblk;
	return 0;
}

static int z_erofs_load_lcluster_from_disk(struct z_erofs_maprecorder *m,
					   unsigned int lcn, bool lookahead)
{
	switch (m->inode->datalayout) {
	case EROFS_INODE_COMPRESSED_FULL:
		return z_erofs_load_full_lcluster(m, lcn);
	case EROFS_INODE_COMPRESSED_COMPACT:
		return z_erofs_load_compact_lcluster(m, lcn, lookahead);
	default:
		return -EINVAL;
	}
}

static int z_erofs_extent_lookback(struct z_erofs_maprecorder *m,
				   unsigned int lookback_distance)
{
	struct erofs_inode *const vi = m->inode;
	const unsigned int lclusterbits = vi->z_lclusterbits;

	while (m->lcn >= lookback_distance) {
		unsigned long lcn = m->lcn - lookback_distance;
		int err;

		err = z_erofs_load_lcluster_from_disk(m, lcn, false);
		if (err)
			return err;

		if (m->type >= Z_EROFS_LCLUSTER_TYPE_MAX) {
			erofs_err("unknown type %u @ lcn %lu of nid %llu",
				  m->type, lcn, vi->nid | 0ULL);
			DBG_BUGON(1);
			return -EOPNOTSUPP;
		} else if (m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
			lookback_distance = m->delta[0];
			if (!lookback_distance)
				break;
			continue;
		} else {
			m->headtype = m->type;
			m->map->m_la = (lcn << lclusterbits) | m->clusterofs;
			return 0;
		}
	}
	erofs_err("bogus lookback distance %u @ lcn %lu of nid %llu",
		  lookback_distance, m->lcn | 0ULL, vi->nid);
	DBG_BUGON(1);
	return -EFSCORRUPTED;
}

static int z_erofs_get_extent_compressedlen(struct z_erofs_maprecorder *m,
					    unsigned int initial_lcn)
{
	struct erofs_inode *const vi = m->inode;
	struct erofs_sb_info *sbi = vi->sbi;
	bool bigpcl1 = vi->z_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1;
	bool bigpcl2 = vi->z_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_2;
	unsigned long lcn = m->lcn + 1;
	int err;

	DBG_BUGON(m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD);
	DBG_BUGON(m->type != m->headtype);

	if ((m->headtype == Z_EROFS_LCLUSTER_TYPE_HEAD1 && !bigpcl1) ||
	    ((m->headtype == Z_EROFS_LCLUSTER_TYPE_PLAIN ||
	      m->headtype == Z_EROFS_LCLUSTER_TYPE_HEAD2) && !bigpcl2) ||
	    (lcn << vi->z_lclusterbits) >= vi->i_size)
		m->compressedblks = 1;

	if (m->compressedblks)
		goto out;

	err = z_erofs_load_lcluster_from_disk(m, lcn, false);
	if (err)
		return err;

	/*
	 * If the 1st NONHEAD lcluster has already been handled initially w/o
	 * valid compressedblks, which means at least it mustn't be CBLKCNT, or
	 * an internal implemenatation error is detected.
	 *
	 * The following code can also handle it properly anyway, but let's
	 * BUG_ON in the debugging mode only for developers to notice that.
	 */
	DBG_BUGON(lcn == initial_lcn &&
		  m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD);

	if (m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
		if (m->delta[0] != 1) {
			erofs_err("bogus CBLKCNT @ lcn %lu of nid %llu",
				  lcn, vi->nid | 0ULL);
			DBG_BUGON(1);
			return -EFSCORRUPTED;
		}
		if (m->compressedblks)
			goto out;
	} else if (m->type < Z_EROFS_LCLUSTER_TYPE_MAX) {
		/*
		 * if the 1st NONHEAD lcluster is actually PLAIN or HEAD type
		 * rather than CBLKCNT, it's a 1 block-sized pcluster.
		 */
		m->compressedblks = 1;
		goto out;
	}
	erofs_err("cannot found CBLKCNT @ lcn %lu of nid %llu",
		  lcn, vi->nid | 0ULL);
	DBG_BUGON(1);
	return -EFSCORRUPTED;
out:
	m->map->m_plen = erofs_pos(sbi, m->compressedblks);
	return 0;
}

static int z_erofs_get_extent_decompressedlen(struct z_erofs_maprecorder *m)
{
	struct erofs_inode *const vi = m->inode;
	struct erofs_map_blocks *map = m->map;
	unsigned int lclusterbits = vi->z_lclusterbits;
	u64 lcn = m->lcn, headlcn = map->m_la >> lclusterbits;
	int err;

	while (1) {
		/* handle the last EOF pcluster (no next HEAD lcluster) */
		if ((lcn << lclusterbits) >= vi->i_size) {
			map->m_llen = vi->i_size - map->m_la;
			return 0;
		}

		err = z_erofs_load_lcluster_from_disk(m, lcn, true);
		if (err)
			return err;

		if (m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
			/* work around invalid d1 generated by pre-1.0 mkfs */
			if (__erofs_unlikely(!m->delta[1])) {
				m->delta[1] = 1;
				DBG_BUGON(1);
			}
		} else if (m->type < Z_EROFS_LCLUSTER_TYPE_MAX) {
			if (lcn != headlcn)
				break;	/* ends at the next HEAD lcluster */
			m->delta[1] = 1;
		} else {
			erofs_err("unknown type %u @ lcn %llu of nid %llu",
				  m->type, lcn | 0ULL,
				  (unsigned long long)vi->nid);
			DBG_BUGON(1);
			return -EOPNOTSUPP;
		}
		lcn += m->delta[1];
	}
	map->m_llen = (lcn << lclusterbits) + m->clusterofs - map->m_la;
	return 0;
}

static int z_erofs_map_blocks_fo(struct erofs_inode *vi,
				 struct erofs_map_blocks *map,
				 int flags)
{
	struct erofs_sb_info *sbi = vi->sbi;
	bool fragment = vi->z_advise & Z_EROFS_ADVISE_FRAGMENT_PCLUSTER;
	bool ztailpacking = vi->z_idata_size;
	unsigned int lclusterbits = vi->z_lclusterbits;
	struct z_erofs_maprecorder m = {
		.inode = vi,
		.map = map,
	};
	int err = 0;
	unsigned int endoff, afmt;
	unsigned long initial_lcn;
	unsigned long long ofs, end;

	ofs = flags & EROFS_GET_BLOCKS_FINDTAIL ? vi->i_size - 1 : map->m_la;
	if (fragment && !(flags & EROFS_GET_BLOCKS_FINDTAIL) &&
	    !vi->z_tailextent_headlcn) {
		map->m_la = 0;
		map->m_llen = vi->i_size;
		map->m_flags = EROFS_MAP_FRAGMENT;
		return 0;
	}
	initial_lcn = ofs >> lclusterbits;
	endoff = ofs & ((1 << lclusterbits) - 1);

	err = z_erofs_load_lcluster_from_disk(&m, initial_lcn, false);
	if (err)
		goto out;

	if ((flags & EROFS_GET_BLOCKS_FINDTAIL) && ztailpacking)
		vi->z_fragmentoff = m.nextpackoff;
	map->m_flags = EROFS_MAP_MAPPED | EROFS_MAP_ENCODED;
	end = (m.lcn + 1ULL) << lclusterbits;

	switch (m.type) {
	case Z_EROFS_LCLUSTER_TYPE_PLAIN:
	case Z_EROFS_LCLUSTER_TYPE_HEAD1:
	case Z_EROFS_LCLUSTER_TYPE_HEAD2:
		if (endoff >= m.clusterofs) {
			m.headtype = m.type;
			map->m_la = (m.lcn << lclusterbits) | m.clusterofs;
			/*
			 * For ztailpacking files, in order to inline data more
			 * effectively, special EOF lclusters are now supported
			 * which can have three parts at most.
			 */
			if (ztailpacking && end > vi->i_size)
				end = vi->i_size;
			break;
		}
		/* m.lcn should be >= 1 if endoff < m.clusterofs */
		if (!m.lcn) {
			erofs_err("invalid logical cluster 0 at nid %llu",
				  (unsigned long long)vi->nid);
			err = -EFSCORRUPTED;
			goto out;
		}
		end = (m.lcn << lclusterbits) | m.clusterofs;
		map->m_flags |= EROFS_MAP_FULL_MAPPED;
		m.delta[0] = 1;
		__erofs_fallthrough;
	case Z_EROFS_LCLUSTER_TYPE_NONHEAD:
		/* get the corresponding first chunk */
		err = z_erofs_extent_lookback(&m, m.delta[0]);
		if (err)
			goto out;
		break;
	default:
		erofs_err("unknown type %u @ offset %llu of nid %llu",
			  m.type, ofs, (unsigned long long)vi->nid);
		err = -EOPNOTSUPP;
		goto out;
	}
	if (m.partialref)
		map->m_flags |= EROFS_MAP_PARTIAL_REF;
	map->m_llen = end - map->m_la;

	if (flags & EROFS_GET_BLOCKS_FINDTAIL) {
		vi->z_tailextent_headlcn = m.lcn;
		/* for non-compact indexes, fragmentoff is 64 bits */
		if (fragment && vi->datalayout == EROFS_INODE_COMPRESSED_FULL)
			vi->fragmentoff |= (u64)m.pblk << 32;
	}
	if (ztailpacking && m.lcn == vi->z_tailextent_headlcn) {
		map->m_flags |= EROFS_MAP_META;
		map->m_pa = vi->z_fragmentoff;
		map->m_plen = vi->z_idata_size;
		if (erofs_blkoff(sbi, map->m_pa) + map->m_plen > erofs_blksiz(sbi)) {
			erofs_err("invalid tail-packing pclustersize %llu",
				  map->m_plen | 0ULL);
			goto out;
		}
	} else if (fragment && m.lcn == vi->z_tailextent_headlcn) {
		map->m_flags = EROFS_MAP_FRAGMENT;
	} else {
		map->m_pa = erofs_pos(sbi, m.pblk);
		err = z_erofs_get_extent_compressedlen(&m, initial_lcn);
		if (err)
			goto out;
	}

	if (m.headtype == Z_EROFS_LCLUSTER_TYPE_PLAIN) {
		if (map->m_llen > map->m_plen) {
			DBG_BUGON(1);
			err = -EFSCORRUPTED;
			goto out;
		}
		afmt = vi->z_advise & Z_EROFS_ADVISE_INTERLACED_PCLUSTER ?
			Z_EROFS_COMPRESSION_INTERLACED :
			Z_EROFS_COMPRESSION_SHIFTED;
	} else {
		afmt = m.headtype == Z_EROFS_LCLUSTER_TYPE_HEAD2 ?
			vi->z_algorithmtype[1] : vi->z_algorithmtype[0];
		if (!(sbi->available_compr_algs & (1 << afmt))) {
			erofs_err("inconsistent algorithmtype %u for nid %llu",
				  afmt, vi->nid);
			err = -EFSCORRUPTED;
			goto out;
		}
	}
	map->m_algorithmformat = afmt;

	if (flags & EROFS_GET_BLOCKS_FIEMAP) {
		err = z_erofs_get_extent_decompressedlen(&m);
		if (!err)
			map->m_flags |= EROFS_MAP_FULL_MAPPED;
	}

out:
	erofs_dbg("m_la %" PRIu64 " m_pa %" PRIu64 " m_llen %" PRIu64 " m_plen %" PRIu64 " m_flags 0%o",
		  map->m_la, map->m_pa,
		  map->m_llen, map->m_plen, map->m_flags);
	return err;
}

static int z_erofs_map_blocks_ext(struct erofs_inode *vi,
				  struct erofs_map_blocks *map, int flags)
{
	struct erofs_sb_info *sbi = vi->sbi;
	bool interlaced = vi->z_advise & Z_EROFS_ADVISE_INTERLACED_PCLUSTER;
	unsigned int recsz = z_erofs_extent_recsize(vi->z_advise);
	erofs_off_t pos = round_up(Z_EROFS_MAP_HEADER_END(erofs_iloc(vi) +
				   vi->inode_isize + vi->xattr_isize), recsz);
	bool in_mbox = erofs_inode_in_metabox(vi);
	erofs_off_t lend = vi->i_size;
	erofs_off_t l, r, mid, pa, la, lstart;
	struct z_erofs_extent *ext;
	unsigned int fmt;
	bool last;

	map->m_flags = 0;
	if (recsz <= offsetof(struct z_erofs_extent, pstart_hi)) {
		if (recsz <= offsetof(struct z_erofs_extent, pstart_lo)) {
			ext = erofs_read_metabuf(&map->buf, sbi, pos, in_mbox);
			if (IS_ERR(ext))
				return PTR_ERR(ext);
			pa = le64_to_cpu(*(__le64 *)ext);
			pos += sizeof(__le64);
			lstart = 0;
		} else {
			lstart = map->m_la >> vi->z_lclusterbits;
			pa = EROFS_NULL_ADDR;
		}

		for (; lstart <= map->m_la; lstart += 1 << vi->z_lclusterbits) {
			ext = erofs_read_metabuf(&map->buf, sbi, pos, in_mbox);
			if (IS_ERR(ext))
				return PTR_ERR(ext);
			map->m_plen = le32_to_cpu(ext->plen);
			if (pa != EROFS_NULL_ADDR) {
				map->m_pa = pa;
				pa += map->m_plen & Z_EROFS_EXTENT_PLEN_MASK;
			} else {
				map->m_pa = le32_to_cpu(ext->pstart_lo);
			}
			pos += recsz;
		}
		last = (lstart >= round_up(lend, 1 << vi->z_lclusterbits));
		lend = min(lstart, lend);
		lstart -= 1ULL << vi->z_lclusterbits;
	} else {
		lstart = lend;
		for (l = 0, r = vi->z_extents; l < r; ) {
			mid = l + (r - l) / 2;
			ext = erofs_read_metabuf(&map->buf, sbi,
						 pos + mid * recsz, in_mbox);
			if (IS_ERR(ext))
				return PTR_ERR(ext);

			la = le32_to_cpu(ext->lstart_lo);
			pa = le32_to_cpu(ext->pstart_lo) |
				(u64)le32_to_cpu(ext->pstart_hi) << 32;
			if (recsz > offsetof(struct z_erofs_extent, lstart_hi))
				la |= (u64)le32_to_cpu(ext->lstart_hi) << 32;

			if (la > map->m_la) {
				r = mid;
				if (la > lend) {
					DBG_BUGON(1);
					return -EFSCORRUPTED;
				}
				lend = la;
			} else {
				l = mid + 1;
				if (map->m_la == la)
					r = min(l + 1, r);
				lstart = la;
				map->m_plen = le32_to_cpu(ext->plen);
				map->m_pa = pa;
			}
		}
		last = (l >= vi->z_extents);
	}

	if (lstart < lend) {
		map->m_la = lstart;
		if (last && (vi->z_advise & Z_EROFS_ADVISE_FRAGMENT_PCLUSTER)) {
			map->m_flags = EROFS_MAP_FRAGMENT;
			vi->z_fragmentoff = map->m_plen;
			if (recsz > offsetof(struct z_erofs_extent, pstart_lo))
				vi->z_fragmentoff |= map->m_pa << 32;
		} else if (map->m_plen) {
			map->m_flags |= EROFS_MAP_MAPPED |
				EROFS_MAP_FULL_MAPPED | EROFS_MAP_ENCODED;
			fmt = map->m_plen >> Z_EROFS_EXTENT_PLEN_FMT_BIT;
			if (fmt)
				map->m_algorithmformat = fmt - 1;
			else if (interlaced && !erofs_blkoff(sbi, map->m_pa))
				map->m_algorithmformat =
					Z_EROFS_COMPRESSION_INTERLACED;
			else
				map->m_algorithmformat =
					Z_EROFS_COMPRESSION_SHIFTED;
			if (map->m_plen & Z_EROFS_EXTENT_PLEN_PARTIAL)
				map->m_flags |= EROFS_MAP_PARTIAL_REF;
			map->m_plen &= Z_EROFS_EXTENT_PLEN_MASK;
		}
	}
	map->m_llen = lend - map->m_la;
	return 0;
}

static int z_erofs_fill_inode_lazy(struct erofs_inode *vi)
{
	struct erofs_sb_info *sbi = vi->sbi;
	int err = 0, headnr;
	erofs_off_t pos;
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	struct z_erofs_map_header *h;

	if (erofs_atomic_read(&vi->flags) & EROFS_I_Z_INITED)
		return 0;

	pos = round_up(erofs_iloc(vi) + vi->inode_isize + vi->xattr_isize, 8);
	h = erofs_read_metabuf(&buf, sbi, pos, erofs_inode_in_metabox(vi));
	if (IS_ERR(h))
		return PTR_ERR(h);

	/*
	 * if the highest bit of the 8-byte map header is set, the whole file
	 * is stored in the packed inode. The rest bits keeps z_fragmentoff.
	 */
	if (h->h_clusterbits >> Z_EROFS_FRAGMENT_INODE_BIT) {
		vi->z_advise = Z_EROFS_ADVISE_FRAGMENT_PCLUSTER;
		vi->fragmentoff = le64_to_cpu(*(__le64 *)h) ^ (1ULL << 63);
		vi->z_tailextent_headlcn = 0;
		goto done;
	}

	vi->z_advise = le16_to_cpu(h->h_advise);
	vi->z_lclusterbits = sbi->blkszbits + (h->h_clusterbits & 15);
	if (vi->datalayout == EROFS_INODE_COMPRESSED_FULL &&
	    (vi->z_advise & Z_EROFS_ADVISE_EXTENTS)) {
		vi->z_extents = le32_to_cpu(h->h_extents_lo) |
			((u64)le16_to_cpu(h->h_extents_hi) << 32);
		goto done;
	}
	vi->z_algorithmtype[0] = h->h_algorithmtype & 15;
	vi->z_algorithmtype[1] = h->h_algorithmtype >> 4;
	if (vi->z_advise & Z_EROFS_ADVISE_FRAGMENT_PCLUSTER)
		vi->z_fragmentoff = le32_to_cpu(h->h_fragmentoff);
	else if (vi->z_advise & Z_EROFS_ADVISE_INLINE_PCLUSTER)
		vi->z_idata_size = le16_to_cpu(h->h_idata_size);

	headnr = 0;
	if (vi->z_algorithmtype[0] >= Z_EROFS_COMPRESSION_MAX ||
	    vi->z_algorithmtype[++headnr] >= Z_EROFS_COMPRESSION_MAX) {
		erofs_err("unknown HEAD%u format %u for nid %llu",
			  headnr + 1, vi->z_algorithmtype[0], vi->nid | 0ULL);
		err = -EOPNOTSUPP;
		goto out_put_metabuf;
	}

	if (vi->datalayout == EROFS_INODE_COMPRESSED_COMPACT &&
	    !(vi->z_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1) ^
	    !(vi->z_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_2)) {
		erofs_err("big pcluster head1/2 of compact indexes should be consistent for nid %llu",
			  vi->nid * 1ULL);
		err = -EFSCORRUPTED;
		goto out_put_metabuf;
	}

	if (vi->z_idata_size ||
	    (vi->z_advise & Z_EROFS_ADVISE_FRAGMENT_PCLUSTER)) {
		struct erofs_map_blocks map = { .buf = __EROFS_BUF_INITIALIZER };

		err = z_erofs_map_blocks_fo(vi, &map,
					    EROFS_GET_BLOCKS_FINDTAIL);
		if (err < 0)
			return err;
	}
done:
	erofs_atomic_set_bit(EROFS_I_Z_INITED_BIT, &vi->flags);
out_put_metabuf:
	erofs_put_metabuf(&buf);
	return err;
}

int z_erofs_map_blocks_iter(struct erofs_inode *vi,
			    struct erofs_map_blocks *map, int flags)
{
	int err = 0;

	if (map->m_la >= vi->i_size) {	/* post-EOF unmapped extent */
		map->m_llen = map->m_la + 1 - vi->i_size;
		map->m_la = vi->i_size;
		map->m_flags = 0;
	} else {
		err = z_erofs_fill_inode_lazy(vi);
		if (!err) {
			if (vi->datalayout == EROFS_INODE_COMPRESSED_FULL &&
			    (vi->z_advise & Z_EROFS_ADVISE_EXTENTS))
				err = z_erofs_map_blocks_ext(vi, map, flags);
			else
				err = z_erofs_map_blocks_fo(vi, map, flags);
		}
		if (!err && (map->m_flags & EROFS_MAP_ENCODED) &&
		    __erofs_unlikely(map->m_plen > Z_EROFS_PCLUSTER_MAX_SIZE ||
				     map->m_llen > Z_EROFS_PCLUSTER_MAX_DSIZE))
			err = -EOPNOTSUPP;
		if (err)
			map->m_llen = 0;
	}
	return err;
}
