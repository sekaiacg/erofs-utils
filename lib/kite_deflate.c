// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * erofs-utils/lib/kite_deflate.c
 *
 * Copyright (C) 2023, Alibaba Cloud
 * Copyright (C) 2023, Gao Xiang <xiang@kernel.org>
 */
#include "erofs/defs.h"
#include "erofs/print.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

unsigned long erofs_memcmp2(const u8 *s1, const u8 *s2,
			    unsigned long sz);

#ifdef TEST
#define kite_dbg(x, ...)	fprintf(stderr, x "\n", ##__VA_ARGS__)
#else
#define kite_dbg(x, ...)
#endif

#define kHistorySize32		(1U << 15)

#define kNumLenSymbols32	256
#define kNumLenSymbolsMax	kNumLenSymbols32

#define kSymbolEndOfBlock	256
#define kSymbolMatch		(kSymbolEndOfBlock + 1)
#define kNumLenSlots		29
#define kMainTableSize		(kSymbolMatch + kNumLenSlots)

#define kFixedLenTableSize	(kSymbolMatch + 31)
#define FixedDistTableSize	32

#define kMainTableSize		(kSymbolMatch + kNumLenSlots)
#define kDistTableSize32	30

#define kNumLitLenCodesMin	257
#define kNumDistCodesMin	1

#define kNumLensCodesMin	4
#define kLensTableSize		19

#define kMatchMinLen		3
#define kMatchMaxLen32		kNumLenSymbols32 + kMatchMinLen - 1

#define kTableDirectLevels      16
#define kBitLensRepNumber_3_6   kTableDirectLevels
#define kBitLens0Number_3_10    (kBitLensRepNumber_3_6 + 1)
#define kBitLens0Number_11_138  (kBitLens0Number_3_10 + 1)

#define kMaxLen                 (kTableDirectLevels - 1)

static u32 kstaticHuff_mainCodes[kFixedLenTableSize];
static const u8 kstaticHuff_litLenLevels[kFixedLenTableSize] = {
	[0   ... 143] = 8, [144 ... 255] = 9,
	[256 ... 279] = 7, [280 ... 287] = 8,
};
static u32 kstaticHuff_distCodes[kFixedLenTableSize];

const u8 kLenStart32[kNumLenSlots] =
	{0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,32,40,48,56,64,80,96,112,128,160,192,224, 255};

const u8 kLenExtraBits32[kNumLenSlots] =
	{0,0,0,0,0,0,0,0,1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4,  4,  5,
	 5,  5,  5, 0};

/* First normalized distance for each code (0 = distance of 1) */
const u32 kDistStart[kDistTableSize32] =
	{0,1,2,3,4,6,8,12,16,24,32,48,64,96,128,192,256,384,512,768,
	 1024,1536,2048,3072,4096,6144,8192,12288,16384,24576};

/* extra bits for each distance code */
const u8 kDistExtraBits[kDistTableSize32] =
	{0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};

const u8 kCodeLengthAlphabetOrder[kLensTableSize] =
	{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

const u8 kLevelExtraBits[3] = {2, 3, 7};

#define kStored			0
#define kFixedHuffman		1
#define kDynamicHuffman		2

struct kite_deflate_symbol {
	u16 len, dist;
};

struct kite_deflate_table {
	u32  mainCodes[kMainTableSize];
	u8   litLenLevels[kMainTableSize];
	u32  distCodes[kDistTableSize32];
	u8   distLevels[kDistTableSize32];
	u32  levelCodes[kLensTableSize];
	u8   levelLens[kLensTableSize];

	u8   numdistlens, numblcodes;
	u16  numlitlens;
};

struct kite_deflate {
	struct kite_deflate_table  *tab;
	const u8   *in;
	u8         *out;

	u32  inlen, outlen;
	u32  pos_in, pos_out;
	u32  inflightbits;
	u8   bitpos;
	u8   numHuffBits;
	u32  symbols;

	u32  costbits, startpos;
	u8   encode_mode;
	bool freq_changed, lastblock;

	/* Previous match for lazy matching */
	bool prev_valid;
	u16 prev_longest;

	u32  mainFreqs[kMainTableSize];
	u32  distFreqs[kDistTableSize32];
	struct kite_deflate_table tables[2];

	/* don't reset the following fields */
	struct kite_matchfinder *mf;
	struct kite_deflate_symbol *sym;
	u32 max_symbols;
	bool lazy_search;
};

#define ZLIB_DISTANCE_TOO_FAR	4096

static u8 g_LenSlots[kNumLenSymbolsMax];

#define kNumLogBits 9		// do not change it
static u8 g_FastPos[1 << kNumLogBits];

static void writebits(struct kite_deflate *s, unsigned int v, u8 bits)
{
	unsigned int rem = sizeof(s->inflightbits) * 8 - s->bitpos;

	s->inflightbits |= (v << s->bitpos) & (!rem - 1);
	if (bits > rem) {
		u8 *out = s->out + s->pos_out;

		out[0] = s->inflightbits & 0xff;
		out[1] = (s->inflightbits >> 8) & 0xff;
		out[2] = (s->inflightbits >> 16) & 0xff;
		out[3] = (s->inflightbits >> 24) & 0xff;
		s->pos_out += 4;
		DBG_BUGON(s->pos_out > s->outlen);
		s->inflightbits = v >> rem;
		s->bitpos = bits - rem;
		return;
	}
	s->bitpos += bits;
}

static void flushbits(struct kite_deflate *s)
{
	u8 *out = s->out + s->pos_out;

	if (!s->bitpos)
		return;
	out[0] = s->inflightbits & 0xff;
	if (s->bitpos >= 8) {
		out[1] = (s->inflightbits >> 8) & 0xff;
		if (s->bitpos >= 16) {
			out[2] = (s->inflightbits >> 16) & 0xff;
			if (s->bitpos >= 24)
				out[3] = (s->inflightbits >> 24) & 0xff;
		}
	}
	s->pos_out += round_up(s->bitpos, 8) >> 3;
	DBG_BUGON(s->pos_out > s->outlen);
	s->bitpos = 0;
	s->inflightbits = 0;
}

static void deflate_genhuffcodes(const u8 *lens, u32 *p, unsigned int nr_codes,
				 const u32 *bl_count)
{
	u32 nextCodes[kMaxLen + 1];	/* next code value for each bit length */
	unsigned int code = 0;		/* running code value */
	unsigned int bits, k;

	for (bits = 1; bits <= kMaxLen; ++bits) {
		code = (code + bl_count[bits - 1]) << 1;
		nextCodes[bits] = code;
	}

	DBG_BUGON(code + bl_count[kMaxLen] != 1 << kMaxLen);

	for (k = 0; k < nr_codes; ++k)
		p[k] = nextCodes[lens[k]]++;
}

static u32 deflate_reversebits_one(u32 code, u8 bits)
{
	unsigned int x = code;

	x = ((x & 0x5555) << 1) | ((x & 0xAAAA) >> 1);
	x = ((x & 0x3333) << 2) | ((x & 0xCCCC) >> 2);
	x = ((x & 0x0F0F) << 4) | ((x & 0xF0F0) >> 4);

	return (((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8)) >> (16 - bits);
}

static void Huffman_ReverseBits(u32 *codes, const u8 *lens, unsigned int n)
{
	while (n) {
		u32 code = *codes;

		*codes++ = deflate_reversebits_one(code, *lens++);
		--n;
	}
}

static void kite_deflate_init_once(void)
{
	static const u32 static_bl_count[kMaxLen + 1] = {
		[7] = 279 - 256 + 1,
		[8] = (143 + 1) + (287 - 280 + 1),
		[9] = 255 - 144 + 1,
	};
	unsigned int i, c, j, k;

	if (kstaticHuff_distCodes[31])
		return;
	deflate_genhuffcodes(kstaticHuff_litLenLevels, kstaticHuff_mainCodes,
			     kFixedLenTableSize, static_bl_count);
	Huffman_ReverseBits(kstaticHuff_mainCodes, kstaticHuff_litLenLevels,
			    kFixedLenTableSize);

	for (i = 0; i < ARRAY_SIZE(kstaticHuff_distCodes); ++i)
		kstaticHuff_distCodes[i] = deflate_reversebits_one(i, 5);

	for (i = 0; i < kNumLenSlots; i++) {
		c = kLenStart32[i];
		j = 1 << kLenExtraBits32[i];

		for (k = 0; k < j; k++, c++)
			g_LenSlots[c] = (u8)i;
	}

	c = 0;
	for (i = 0; i < /*kFastSlots*/ kNumLogBits * 2; i++) {
		k = 1 << kDistExtraBits[i];
		for (j = 0; j < k; j++)
			g_FastPos[c++] = i;
	}
}

static void kite_deflate_scanlens(unsigned int numlens, u8 *lens, u32 *freqs)
{
	int n;				/* iterates over all tree elements */
	int prevlen = -1;		/* last emitted length */
	int curlen;			/* length of current code */
	int nextlen = lens[0];		/* length of next code */
	int count = 0;			/* repeat count of the current code */
	int max_count = 7;		/* max repeat count */
	int min_count = 4;		/* min repeat count */

	if (!nextlen)
		max_count = 138, min_count = 3;

	for (n = 0; n < numlens; n++) {
		curlen = nextlen;
		nextlen = n + 1 < numlens ? lens[n + 1] : -1;
		++count;

		if (count < max_count && curlen == nextlen)
			continue;
		if (count < min_count) {
			freqs[curlen] += count;
		} else if (curlen != 0) {
			if (curlen != prevlen)
				freqs[curlen]++;
			freqs[kBitLensRepNumber_3_6]++;
		} else if (count <= 10) {
			freqs[kBitLens0Number_3_10]++;
		} else {
			freqs[kBitLens0Number_11_138]++;
		}

		count = 0;
		prevlen = curlen;
		if (!nextlen)
			max_count = 138, min_count = 3;
		else if (curlen == nextlen)
			max_count = 6, min_count = 3;
		else
			max_count = 7, min_count = 4;
	}
}

static void kite_deflate_sendtree(struct kite_deflate *s, const u8 *lens,
				  unsigned int numlens)
{
	int n;				/* iterates over all tree elements */
	int prevlen = -1;		/* last emitted length */
	int curlen;			/* length of current code */
	int nextlen = lens[0];		/* length of next code */
	int count = 0;			/* repeat count of the current code */
	int max_count = 7;		/* max repeat count */
	int min_count = 4;		/* min repeat count */
	const u8 *bl_lens = s->tab->levelLens;
	const u32 *bl_codes = s->tab->levelCodes;

	if (!nextlen)
		max_count = 138, min_count = 3;

	for (n = 0; n < numlens; n++) {
		curlen = nextlen;
		nextlen = n + 1 < numlens ? lens[n + 1] : -1;
		++count;

		if (count < max_count && curlen == nextlen)
			continue;
		if (count < min_count) {
			do {
				writebits(s, bl_codes[curlen], bl_lens[curlen]);
			} while (--count);
		} else if (curlen) {
			if (curlen != prevlen) {
				writebits(s, bl_codes[curlen], bl_lens[curlen]);
				count--;
			}
			writebits(s, bl_codes[kBitLensRepNumber_3_6],
				  bl_lens[kBitLensRepNumber_3_6]);
			writebits(s, count - 3, 2);
		} else if (count <= 10) {
			writebits(s, bl_codes[kBitLens0Number_3_10],
				  bl_lens[kBitLens0Number_3_10]);
			writebits(s, count - 3, 3);
		} else {
			writebits(s, bl_codes[kBitLens0Number_11_138],
				  bl_lens[kBitLens0Number_11_138]);
			writebits(s, count - 11, 7);
		}

		count = 0;
		prevlen = curlen;
		if (!nextlen)
			max_count = 138, min_count = 3;
		else if (curlen == nextlen)
			max_count = 6, min_count = 3;
		else
			max_count = 7, min_count = 4;
	}
}

static void kite_deflate_setfixedtrees(struct kite_deflate *s)
{
	writebits(s, (kFixedHuffman << 1) + s->lastblock, 3);
}

static void kite_deflate_sendtrees(struct kite_deflate *s)
{
	struct kite_deflate_table *t = s->tab;
	unsigned int i;

	writebits(s, (kDynamicHuffman << 1) + s->lastblock, 3);
	writebits(s, t->numlitlens - kNumLitLenCodesMin, 5);
	writebits(s, t->numdistlens - kNumDistCodesMin,  5);
	writebits(s, t->numblcodes - kNumLensCodesMin,   4);

	for (i = 0; i < t->numblcodes; i++)
		writebits(s, t->levelLens[kCodeLengthAlphabetOrder[i]], 3);

	Huffman_ReverseBits(t->levelCodes, t->levelLens, kLensTableSize);
	kite_deflate_sendtree(s, t->litLenLevels, t->numlitlens);
	kite_deflate_sendtree(s, t->distLevels, t->numdistlens);
}

static inline unsigned int deflateDistSlot(unsigned int pos)
{
	const unsigned int zz = (kNumLogBits - 1) &
		((((1U << kNumLogBits) - 1) - pos) >> (31 - 3));

	return g_FastPos[pos >> zz] + (zz * 2);
}

static void kite_deflate_writeblock(struct kite_deflate *s, bool fixed)
{
	int i;
	u32 *mainCodes, *distCodes;
	const u8 *litLenLevels, *distLevels;

	if (!fixed) {
		struct kite_deflate_table *t = s->tab;

		mainCodes = t->mainCodes; distCodes = t->distCodes;
		litLenLevels = t->litLenLevels;	distLevels = t->distLevels;

		Huffman_ReverseBits(mainCodes, litLenLevels, kMainTableSize);
		Huffman_ReverseBits(distCodes, distLevels, kDistTableSize32);
	} else {
		mainCodes = kstaticHuff_mainCodes;
		distCodes = kstaticHuff_distCodes;

		litLenLevels = kstaticHuff_litLenLevels;
		distLevels = NULL;
	}

	for (i = 0; i < s->symbols; ++i) {
		struct kite_deflate_symbol *sym = &s->sym[i];

		if (sym->len < kMatchMinLen) {		/* literal */
			writebits(s, mainCodes[sym->dist],
				  litLenLevels[sym->dist]);
		} else {
			unsigned int lenSlot, distSlot;
			unsigned int lc = sym->len - kMatchMinLen;

			lenSlot = g_LenSlots[lc];
			writebits(s, mainCodes[kSymbolMatch + lenSlot],
				  litLenLevels[kSymbolMatch + lenSlot]);
			writebits(s, lc - kLenStart32[lenSlot],
				  kLenExtraBits32[lenSlot]);

			distSlot = deflateDistSlot(sym->dist - 1);
			writebits(s, distCodes[distSlot],
				  fixed ? 5 : distLevels[distSlot]);
			writebits(s, sym->dist - 1 - kDistStart[distSlot],
				  kDistExtraBits[distSlot]);
		}
	}
	writebits(s, mainCodes[kSymbolEndOfBlock],
		  litLenLevels[kSymbolEndOfBlock]);
}

static u32 Huffman_GetPrice(const u32 *freqs, const u8 *lens, u32 num)
{
	u32 price = 0;

	while (num) {
		price += (*lens++) * (*freqs++);
		--num;
	}
	return price;
}

static u32 Huffman_GetPriceEx(const u32 *freqs, const u8 *lens, u32 num,
			      const u8 *extraBits, u32 extraBase)
{
	return Huffman_GetPrice(freqs, lens, num) +
		Huffman_GetPrice(freqs + extraBase, extraBits, num - extraBase);
}

/* Adapted from C/HuffEnc.c (7zip) for now */
#define HeapSortDown(p, k, size, temp) \
  { for (;;) { \
    size_t s = (k << 1); \
    if (s > size) break; \
    if (s < size && p[s + 1] > p[s]) s++; \
    if (temp >= p[s]) break; \
    p[k] = p[s]; k = s; \
  } p[k] = temp; }

static void HeapSort(u32 *p, size_t size)
{
  if (size <= 1)
    return;
  p--;
  {
    size_t i = size / 2;
    do
    {
      u32 temp = p[i];
      size_t k = i;
      HeapSortDown(p, k, size, temp)
    }
    while (--i != 0);
  }
  /*
  do
  {
    size_t k = 1;
    UInt32 temp = p[size];
    p[size--] = p[1];
    HeapSortDown(p, k, size, temp)
  }
  while (size > 1);
  */
  while (size > 3)
  {
    u32 temp = p[size];
    size_t k = (p[3] > p[2]) ? 3 : 2;
    p[size--] = p[1];
    p[1] = p[k];
    HeapSortDown(p, k, size, temp)
  }
  {
    u32 temp = p[size];
    p[size] = p[1];
    if (size > 2 && p[2] < temp)
    {
      p[1] = p[2];
      p[2] = temp;
    }
    else
      p[1] = temp;
  }
}

#define NUM_BITS 10
#define MASK (((unsigned)1 << NUM_BITS) - 1)

static void Huffman_Generate(const u32 *freqs, u32 *p, u8 *lens,
			     unsigned int numSymbols, unsigned int maxLen)
{
	u32 num, i;

	num = 0;
	/* if (maxLen > 10) maxLen = 10; */

	for (i = 0; i < numSymbols; i++) {
		u32 freq = freqs[i];

		if (!freq)
			lens[i] = 0;
		else
			p[num++] = i | (freq << NUM_BITS);
	}
	HeapSort(p, num);

	if (num < 2) {
		unsigned int minCode = 0, maxCode = 1;

		if (num == 1) {
			maxCode = (unsigned int)p[0] & MASK;
			if (!maxCode)
				maxCode++;
		}
		p[minCode] = 0;
		p[maxCode] = 1;
		lens[minCode] = lens[maxCode] = 1;
		return;
	}

	{
		u32 b, e, i;

		i = b = e = 0;
		do {
			u32 n, m, freq;

			n = (i != num && (b == e || (p[i] >> NUM_BITS) <= (p[b] >> NUM_BITS))) ? i++ : b++;
			freq = (p[n] & ~MASK);
			p[n] = (p[n] & MASK) | (e << NUM_BITS);
			m = (i != num && (b == e || (p[i] >> NUM_BITS) <= (p[b] >> NUM_BITS))) ? i++ : b++;
			freq += (p[m] & ~MASK);
			p[m] = (p[m] & MASK) | (e << NUM_BITS);
			p[e] = (p[e] & MASK) | freq;
			e++;
		} while (num - e > 1);

		{
			u32 lenCounters[kMaxLen + 1];

			for (i = 0; i <= kMaxLen; i++)
				lenCounters[i] = 0;

			p[--e] &= MASK;
			lenCounters[1] = 2;
			while (e > 0) {
				u32 len = (p[p[--e] >> NUM_BITS] >> NUM_BITS) + 1;

				p[e] = (p[e] & MASK) | (len << NUM_BITS);
				if (len >= maxLen)
					for (len = maxLen - 1; lenCounters[len] == 0; len--);
				lenCounters[len]--;
				lenCounters[(size_t)len + 1] += 2;
			}

			{
				u32 len;

				i = 0;
				for (len = maxLen; len != 0; len--) {
					u32 k;
					for (k = lenCounters[len]; k != 0; k--)
						lens[p[i++] & MASK] = (u8)len;
				}
			}
			deflate_genhuffcodes(lens, p, numSymbols, lenCounters);
		}
	}
}

static void kite_deflate_fixdynblock(struct kite_deflate *s)
{
	struct kite_deflate_table *t = s->tab;
	unsigned int numlitlens, numdistlens, numblcodes;
	u32 levelFreqs[kLensTableSize] = {0};
	u32 opt_mainlen;

	if (!s->freq_changed)
		return;

	/* in order to match zlib */
	s->numHuffBits = kMaxLen;
//	s->numHuffBits = (s->symbols > 18000 ? 12 :
//		(s->symbols > 7000 ? 11 : (s->symbols > 2000 ? 10 : 9)));

	Huffman_Generate(s->mainFreqs, t->mainCodes, t->litLenLevels,
			 kMainTableSize, s->numHuffBits);
	Huffman_Generate(s->distFreqs, t->distCodes, t->distLevels,
			 kDistTableSize32, s->numHuffBits);

	/* code lengths for the literal/length alphabet */
	numlitlens = kMainTableSize;
	while (numlitlens > kNumLitLenCodesMin &&
	       !t->litLenLevels[numlitlens - 1])
		--numlitlens;

	/* code lengths for the distance alphabet */
	numdistlens = kDistTableSize32;
	while (numdistlens > kNumDistCodesMin &&
	       !t->distLevels[numdistlens - 1])
		--numdistlens;

	kite_deflate_scanlens(numlitlens, t->litLenLevels, levelFreqs);
	kite_deflate_scanlens(numdistlens, t->distLevels, levelFreqs);
	Huffman_Generate(levelFreqs, t->levelCodes, t->levelLens,
			 kLensTableSize, 7);
	numblcodes = kLensTableSize;
	while (numblcodes > kNumLensCodesMin &&
	       !t->levelLens[kCodeLengthAlphabetOrder[numblcodes - 1]])
		--numblcodes;

	t->numlitlens = numlitlens;
	t->numdistlens = numdistlens;
	t->numblcodes = numblcodes;

	opt_mainlen = Huffman_GetPriceEx(s->mainFreqs, t->litLenLevels,
			kMainTableSize, kLenExtraBits32, kSymbolMatch) +
		Huffman_GetPriceEx(s->distFreqs, t->distLevels,
			kDistTableSize32, kDistExtraBits, 0);
	s->costbits = 3 + 5 + 5 + 4 + 3 * numblcodes +
		Huffman_GetPriceEx(levelFreqs, t->levelLens,
			kLensTableSize, kLevelExtraBits, kTableDirectLevels) +
		opt_mainlen;
	s->freq_changed = false;
}


/*
 * an array used used by the LZ-based encoder to hold the length-distance pairs
 * found by LZ matchfinder.
 */
struct kite_match {
	unsigned int len;
	unsigned int dist;
};

struct kite_matchfinder {
	/* pointer to buffer with data to be compressed */
	const u8 *buffer;

	/* indicate the first byte that doesn't contain valid input data */
	const u8 *end;

	/* LZ matchfinder hash chain representation */
	u32 *hash, *chain;

	u32 base;

	/* indicate the next byte to run through the match finder */
	u32 offset;

	u32 cyclic_pos;

	/* maximum length of a match that the matchfinder will try to find. */
	u16 nice_len;

	/* the total sliding window size */
	u16 wsiz;

	/* how many rounds a matchfinder searches on a hash chain for */
	u16 depth;

	/* do not perform lazy search no less than this match length */
	u16 max_lazy;

	/* reduce lazy search no less than this match length */
	u8  good_len;

	/* current match for lazy matching */
	struct kite_match *matches;
	struct kite_match matches_matrix[2][4];
};

/*
 * This mysterious table is just the CRC of each possible byte. It can be
 * computed using the standard bit-at-a-time methods. The polynomial can
 * be seen in entry 128, 0x8408. This corresponds to x^0 + x^5 + x^12.
 * Add the implicit x^16, and you have the standard CRC-CCITT.
 */
u16 const crc_ccitt_table[256] __attribute__((__aligned__(128))) = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

int kite_mf_getmatches_hc3(struct kite_matchfinder *mf, u16 depth, u16 bestlen)
{
	const u8 *cur = mf->buffer + mf->offset;
	const u8 *qbase = mf->buffer - mf->base;
	u32 curMatch;
	unsigned int v, hv, i, k, p, wsiz;

	if (mf->end - cur < bestlen + 1)
		return -1;

	v = get_unaligned((u16 *)cur);
	hv = v ^ crc_ccitt_table[cur[2]];
	curMatch = mf->hash[hv];
	p = mf->base + mf->offset;
	mf->hash[hv] = p;
	mf->chain[mf->cyclic_pos] = curMatch;
	wsiz = mf->wsiz;
	k = 1;

	if (depth) {
		unsigned int wpos = wsiz + mf->cyclic_pos;

		hv = min_t(unsigned int, mf->nice_len, mf->end - cur);
		DBG_BUGON(hv > kMatchMaxLen32);
		do {
			unsigned int diff = p - curMatch;
			const u8 *q;

			if (diff >= wsiz)
				break;

			q = qbase + curMatch;
			curMatch = mf->chain[(wpos - diff) & (wsiz - 1)];
			if (v == get_unaligned((u16 *)q) && (bestlen < 3 || (
			    get_unaligned((u16 *)(cur + bestlen - 1)) ==
			    get_unaligned((u16 *)(q + bestlen - 1)) &&
			    !memcmp(cur + 3, q + 3, bestlen - 3)))) {
				DBG_BUGON(cur[2] != q[2]);
				i = erofs_memcmp2(cur + bestlen + 1,
					q + bestlen + 1, hv - bestlen - 1);
				bestlen += 1 + i;

				k -= (k >= ARRAY_SIZE(mf->matches_matrix[0]));
				mf->matches[k++] = (struct kite_match) {
					.len = bestlen,
					.dist = diff,
				};
				if (bestlen >= hv)
					break;
			}
		} while (--depth);
	}
	mf->offset++;
	mf->cyclic_pos = (mf->cyclic_pos + 1) & (wsiz - 1);
	return k - 1;
}

static void kite_mf_hc3_skip(struct kite_matchfinder *mf)
{
	if (kite_mf_getmatches_hc3(mf, 0, 2) >= 0)
		return;
	mf->offset++;
	/* mf->cyclic_pos = (mf->cyclic_pos + 1) & (mf->wsiz - 1); */
}

/* let's align with zlib */
static const struct kite_matchfinder_cfg {
	u16  good_length;	/* reduce lazy search above this match length */
	u16  max_lazy;	/* do not perform lazy search above this match length */
	u16  nice_length;	/* quit search above this match length */
	u16  depth;
	bool lazy_search;
} kite_mfcfg[10] = {
/*      good lazy nice depth */
/* 0 */ {0,    0,  0,    0, false},	/* store only [unsupported] */
/* 1 */ {4,    4,  8,    4, false},	/* maximum speed, no lazy matches */
/* 2 */ {4,    5, 16,    8, false},
/* 3 */ {4,    6, 32,   32, false},

/* 4 */ {4,    4,  16,   16, true},	/* lazy matches */
/* 5 */ {8,   16,  32,   32, true},
/* 6 */ {8,   16, 128,  128, true},
/* 7 */ {8,   32, 128,  256, true},
/* 8 */ {32, 128, 258, 1024, true},
/* 9 */ {32, 258, 258, 4096, true},	/* maximum compression */
};

static int kite_mf_init(struct kite_matchfinder *mf, unsigned int wsiz,
			int level)
{
	const struct kite_matchfinder_cfg *cfg;

	if (!level || level >= ARRAY_SIZE(kite_mfcfg))
		return -EINVAL;
	cfg = &kite_mfcfg[level];

	if (wsiz > kHistorySize32 || (wsiz & (wsiz - 1)))
		return -EINVAL;

	mf->hash = calloc(0x10000, sizeof(mf->hash[0]));
	if (!mf->hash)
		return -ENOMEM;

	mf->chain = malloc(sizeof(mf->chain[0]) * wsiz);
	if (!mf->chain) {
		free(mf->hash);
		mf->hash = NULL;
		return -ENOMEM;
	}
	mf->wsiz = wsiz;

	mf->good_len = cfg->good_length;
	mf->nice_len = cfg->nice_length;
	mf->depth = cfg->depth;
	mf->max_lazy = cfg->max_lazy;
	return cfg->lazy_search;
}

static void kite_mf_reset(struct kite_matchfinder *mf,
			  const void *buffer, const void *end)
{
	mf->buffer = buffer;
	mf->end = end;

	/*
	 * Set the initial value as max_distance + 1.  This would avoid hash
	 * zero initialization.
	 */
	mf->base += mf->offset + kHistorySize32 + 1;

	/*
	 * Unlike other LZ encoders like liblzma [1], we simply reset the hash
	 * chain instead of normalization.  This avoids extra complexity, as we
	 * don't consider extreme large input buffers in one go.
	 *
	 * [1] https://github.com/tukaani-project/xz/blob/v5.4.0/src/liblzma/lz/lz_encoder_mf.c#L94
	 */
	if (__erofs_unlikely(mf->base > ((typeof(mf->base))-1) >> 1)) {
		mf->base = kHistorySize32 + 1;
		memset(mf->hash, 0, 0x10000 * sizeof(mf->hash[0]));
	}
	mf->offset = 0;
	mf->cyclic_pos = 0;

	mf->matches = mf->matches_matrix[0];
	mf->matches_matrix[0][0].len =
		mf->matches_matrix[1][0].len = kMatchMinLen - 1;
}

static bool deflate_count_code(struct kite_deflate *s, bool literal,
			       unsigned int lenSlot, unsigned int distSlot)
{
	struct kite_deflate_table *t = s->tab;
	unsigned int lenbase = (literal ? 0 : kSymbolMatch);
	u64 rem = (s->outlen - s->pos_out) * 8ULL - s->bitpos;
	bool recalc = false;
	unsigned int bits;

	s->freq_changed = true;
	++s->mainFreqs[lenbase + lenSlot];
	if (!literal)
		++s->distFreqs[distSlot];

	if (s->encode_mode == 1) {
		if (literal) {
			bits = kstaticHuff_litLenLevels[lenSlot];
			goto out;
		}
		bits = kstaticHuff_litLenLevels[kSymbolMatch + lenSlot] +
			kLenExtraBits32[lenSlot] + 5 + kDistExtraBits[distSlot];
		goto out;
	}

	/* XXX: more ideas to be done later */
	recalc |= (!literal && !t->distLevels[distSlot]);
	recalc |= !t->litLenLevels[lenbase + lenSlot];
	if (recalc) {
		kite_dbg("recalc %c lS %u dS %u", literal ? 'l' : 'm',
			 lenSlot, distSlot);
		s->tab = s->tables + (s->tab == s->tables);
		kite_deflate_fixdynblock(s);
		bits = 0;
		goto out;
	}

	if (literal) {
		bits = t->litLenLevels[lenSlot];
		goto out;
	}

	bits = t->distLevels[distSlot] + kDistExtraBits[distSlot] +
		t->litLenLevels[kSymbolMatch + lenSlot] +
		kLenExtraBits32[lenSlot];
out:
	if (rem < s->costbits + bits) {
		--s->mainFreqs[lenbase + lenSlot];
		if (!literal)
			--s->distFreqs[distSlot];
		if (recalc)
			s->tab = s->tables + (s->tab == s->tables);
		return false;
	}
	s->costbits += bits;
	return true;
}

static bool kite_deflate_tally(struct kite_deflate *s,
			       struct kite_match *match)
{
	struct kite_deflate_symbol *sym = s->sym + s->symbols;
	u32 fixedcost = ~0;
	bool hassp;

	*sym = (struct kite_deflate_symbol) {
		.len = match->len,
		.dist = match->dist,
	};

retry:
	if (sym->len < kMatchMinLen) {
		hassp = deflate_count_code(s, true, sym->dist, 0);
	} else {
		unsigned int lc = sym->len - kMatchMinLen;
		unsigned int lenSlot = g_LenSlots[lc];
		unsigned int distSlot = deflateDistSlot(sym->dist - 1);

		hassp = deflate_count_code(s, false, lenSlot, distSlot);
	}

	if (!hassp) {
		if (s->encode_mode == 1) {
			fixedcost = s->costbits;
			s->encode_mode = 2;
			goto retry;
		}
		s->lastblock = true;
		if (fixedcost <= s->costbits)
			s->encode_mode = 1;
		return true;
	}
	++s->symbols;
	return false;
}

static void kite_deflate_writestore(struct kite_deflate *s)
{
	bool fb = !s->startpos && !s->bitpos;
	unsigned int totalsiz = s->pos_in - s->prev_valid - s->startpos;

	do {
		unsigned int len = min_t(unsigned int, totalsiz, 65535);

		totalsiz -= len;
		writebits(s, (fb << 3) | (kStored << 1) |
			  (s->lastblock && !totalsiz), 3 + fb);
		flushbits(s);
		writebits(s, len, 16);
		writebits(s, len ^ 0xffff, 16);
		flushbits(s);
		memcpy(s->out + s->pos_out, s->in + s->startpos, len);
		s->pos_out += len;
		s->startpos += len;
	} while (totalsiz);
}

static void kite_deflate_endblock(struct kite_deflate *s)
{
	u64 b = s->outlen - s->pos_out;

	if (s->encode_mode == 1) {
		u32 fixedcost = s->costbits;
		unsigned int storelen, storeblocks, storecost;

		kite_deflate_fixdynblock(s);
		if (fixedcost > s->costbits)
			s->encode_mode = 2;
		else
			s->costbits = fixedcost;

		storelen = s->pos_in - s->prev_valid - s->startpos;
		storeblocks = max(DIV_ROUND_UP(storelen, 65535), 1U);
		storecost = (8 - s->bitpos) + storeblocks - 1 +
			storeblocks * 32 + storelen * 8;
		if (s->costbits > storecost) {
			s->costbits = storecost;
			s->encode_mode = 0;
		}
	}

	if (s->costbits + s->bitpos +
	    3 + kstaticHuff_litLenLevels[kSymbolEndOfBlock] >= b * 8) {
		DBG_BUGON(s->costbits + s->bitpos > b * 8);
		s->lastblock = true;
	}
}

static void kite_deflate_startblock(struct kite_deflate *s)
{
	memset(s->mainFreqs, 0, sizeof(s->mainFreqs));
	memset(s->distFreqs, 0, sizeof(s->distFreqs));
	memset(s->tables, 0, sizeof(s->tables[0]));
	s->symbols = 0;
	s->mainFreqs[kSymbolEndOfBlock]++;
	s->encode_mode = 1;
	s->tab = s->tables;
	s->costbits = 3 + kstaticHuff_litLenLevels[kSymbolEndOfBlock];
}

static bool kite_deflate_commitblock(struct kite_deflate *s)
{
	if (s->encode_mode == 1) {
		kite_deflate_setfixedtrees(s);
		kite_deflate_writeblock(s, true);
	} else if (s->encode_mode == 2) {
		kite_deflate_sendtrees(s);
		kite_deflate_writeblock(s, false);
	} else {
		kite_deflate_writestore(s);
	}
	s->startpos = s->pos_in - s->prev_valid;
	return s->lastblock;
}

static bool kite_deflate_fast(struct kite_deflate *s)
{
	struct kite_matchfinder *mf = s->mf;

	kite_deflate_startblock(s);
	while (1) {
		int matches = kite_mf_getmatches_hc3(mf, mf->depth,
				kMatchMinLen - 1);

		if (matches > 0) {
			unsigned int len = mf->matches[matches].len;
			unsigned int dist = mf->matches[matches].dist;

			if (len == kMatchMinLen && dist > ZLIB_DISTANCE_TOO_FAR)
				goto nomatch;

			kite_dbg("%u matches found: longest [%u,%u] of distance %u",
				 matches, s->pos_in, s->pos_in + len - 1, dist);

			if (kite_deflate_tally(s, mf->matches + matches))
				break;
			s->pos_in += len;
			/* skip the rest bytes */
			while (--len)
				kite_mf_hc3_skip(mf);
		} else {
nomatch:
			mf->matches[0].dist = s->in[s->pos_in];
			if (isprint(s->in[s->pos_in]))
				kite_dbg("literal %c pos_in %u", s->in[s->pos_in], s->pos_in);
			else
				kite_dbg("literal %x pos_in %u", s->in[s->pos_in], s->pos_in);

			if (kite_deflate_tally(s, mf->matches))
				break;
			++s->pos_in;
		}

		s->lastblock |= (s->pos_in >= s->inlen);
		if (s->pos_in >= s->inlen || s->symbols >= s->max_symbols) {
			kite_deflate_endblock(s);
			break;
		}
	}
	return kite_deflate_commitblock(s);
}

static bool kite_deflate_slow(struct kite_deflate *s)
{
	struct kite_matchfinder *mf = s->mf;
	bool flush = false, eos = false;

	kite_deflate_startblock(s);
	while (1) {
		struct kite_match *prev_matches = mf->matches;
		unsigned int len = kMatchMinLen - 1;
		int matches;
		unsigned int len0;

		mf->matches = mf->matches_matrix[
				mf->matches == mf->matches_matrix[0]];
		mf->matches[0].dist = s->in[s->pos_in];

		len0 = prev_matches[s->prev_longest].len;
		if (len0 < mf->max_lazy) {
			matches = kite_mf_getmatches_hc3(mf, mf->depth >>
				(len0 >= mf->good_len), len0);
			if (matches > 0) {
				len = mf->matches[matches].len;
				if (len == kMatchMinLen &&
				    mf->matches[matches].dist > ZLIB_DISTANCE_TOO_FAR) {
					matches = 0;
					len = kMatchMinLen - 1;
				}
			} else {
				matches = 0;
			}
		} else {
			matches = 0;
			kite_mf_hc3_skip(mf);
		}

		if (len < len0) {
			if (kite_deflate_tally(s,
					prev_matches + s->prev_longest))
				break;

			s->pos_in += --len0;
			/* skip the rest bytes */
			while (--len0)
				kite_mf_hc3_skip(mf);
			s->prev_valid = false;
			s->prev_longest = 0;
		} else {
			if (!s->prev_valid)
				s->prev_valid = true;
			else if (kite_deflate_tally(s, prev_matches))
				break;
			++s->pos_in;
			s->prev_longest = matches;
		}

		eos = (s->pos_in >= s->inlen);
		if (eos || s->symbols >= s->max_symbols) {
			s->lastblock |= eos;
			flush = true;
			break;
		}
	}

	if (flush) {
		if (eos && s->prev_valid) {
			if (!kite_deflate_tally(s, mf->matches + s->prev_longest))
				s->prev_valid = false;
		}
		kite_deflate_endblock(s);
	}
	return kite_deflate_commitblock(s);
}

void kite_deflate_end(struct kite_deflate *s)
{
	if (s->mf) {
		if (s->mf->hash)
			free(s->mf->hash);
		if (s->mf->chain)
			free(s->mf->chain);
		free(s->mf);
	}
	if (s->sym)
		free(s->sym);
	free(s);
}

struct kite_deflate *kite_deflate_init(int level, unsigned int dict_size)
{
	struct kite_deflate *s;
	int err;

	kite_deflate_init_once();
	s = calloc(1, sizeof(*s));
	if (!s)
		return ERR_PTR(-ENOMEM);

	s->max_symbols = 16384;
	s->sym = malloc(sizeof(s->sym[0]) * s->max_symbols);
	if (!s->sym) {
		err = -ENOMEM;
		goto err_out;
	}

	s->mf = malloc(sizeof(*s->mf));
	if (!s->mf) {
		err = -ENOMEM;
		goto err_out;
	}

	if (!dict_size)
		dict_size = kHistorySize32;

	err = kite_mf_init(s->mf, dict_size, level);
	if (err < 0)
		goto err_out;

	s->lazy_search = err;
	return s;
err_out:
	if (s->mf)
		free(s->mf);
	if (s->sym)
		free(s->sym);
	free(s);
	return ERR_PTR(err);
}

int kite_deflate_destsize(struct kite_deflate *s, const u8 *in, u8 *out,
			   unsigned int *srcsize, unsigned int target_dstsize)
{
	memset(s, 0, offsetof(struct kite_deflate, mainFreqs));
	s->in = in;
	s->inlen = *srcsize;
	s->out = out;
	s->outlen = target_dstsize;
	kite_mf_reset(s->mf, in, in + s->inlen);

	if (s->lazy_search)
		while (!kite_deflate_slow(s));
	else
		while (!kite_deflate_fast(s));
	flushbits(s);

	*srcsize = s->startpos;
	return s->pos_out;
}

#if TEST
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#ifdef HAVE_ZLIB
#include <zlib.h>

static int kite_deflate_decompress_zlib(const u8 *in, size_t inlen,
					u8 *out, size_t out_capacity)
{
	z_stream z;
	int res;

	memset(&z, 0, sizeof(z));
	res = inflateInit2(&z, -15);
	if (res != Z_OK) {
		DBG_BUGON(1);
		return -1;
	}
	z.next_in = (void *)in;
	z.avail_in = inlen;
	z.next_out = (void *)out;
	z.avail_out = out_capacity;
	res = inflate(&z, Z_FINISH);
	if (res != Z_STREAM_END) {
		DBG_BUGON(1);
		return -1;
	}
	inflateEnd(&z);
	return out_capacity - z.avail_out;
}

static void kite_deflate_decompress_test_zlib(const u8 *in, size_t inlen,
					      u8 *out, size_t out_capacity,
					      const u8 *expected_out,
					      size_t expected_outlen)
{
	int outlen;

	outlen = kite_deflate_decompress_zlib(in, inlen, out, out_capacity);
	BUG_ON(outlen != expected_outlen);
	if (expected_outlen)
		BUG_ON(memcmp(out, expected_out, expected_outlen));
}
#endif

static void kite_deflate_decompress_test(const u8 *in, size_t inlen,
					 u8 *out, size_t out_capacity,
					 const u8 *expected_out,
					 size_t expected_outlen)
{
#ifdef HAVE_ZLIB
	kite_deflate_decompress_test_zlib(in, inlen, out, out_capacity,
					  expected_out, expected_outlen);
#endif
}

static void kite_deflate_test1(void)
{
	struct kite_deflate *s;
	u8 enc[3], vb[10];

	s = kite_deflate_init(1, 0);
	BUG_ON(!s || IS_ERR(s));

	s->out = enc;
	s->outlen = sizeof(enc);

	writebits(s, (kFixedHuffman << 1) + 1, 3);
	writebits(s, kstaticHuff_mainCodes[kSymbolEndOfBlock],
		  kstaticHuff_litLenLevels[kSymbolEndOfBlock]);
	flushbits(s);

	kite_deflate_decompress_test(enc, s->pos_out,
				     vb, sizeof(vb), NULL, 0);
}

int main(int argc, char *argv[])
{
	unsigned int srcsize, outsize, dstsize, level;
	struct kite_deflate *s;
	u8 out[1048576], *buf;
	u64 filelength;
	u8 *vbuf __maybe_unused;
	int fd;

	if (argc < 2) {
		kite_deflate_test1();
		fprintf(stdout, "PASS\n");
		return 0;
	}
	dstsize = level = 0;
	fd = open(argv[1], O_RDONLY);
	BUG_ON(fd < 0);
	if (argc > 2) {
		dstsize = atoi(argv[2]);
		if (argc > 3)
			level = atoi(argv[3]);
	}
	if (!dstsize || dstsize > sizeof(out))
		dstsize = 4096;
	if (!level)
		level = 9;

	s = kite_deflate_init(level, 0);
	BUG_ON(IS_ERR(s));

	filelength = lseek(fd, 0, SEEK_END);
	buf = mmap(NULL, filelength, PROT_READ, MAP_SHARED, fd, 0);
	BUG_ON(buf == MAP_FAILED);
	close(fd);

	srcsize = filelength;
	outsize = kite_deflate_destsize(s, buf, out, &srcsize, dstsize);
	kite_deflate_end(s);
#ifdef HAVE_ZLIB
	vbuf = malloc(srcsize);
	if (!vbuf) {
		fprintf(stderr, "failed to allocate test buffer\n");
	} else {
		BUG_ON(kite_deflate_decompress_zlib(out, outsize,
						    vbuf, srcsize) != srcsize);
		BUG_ON(memcmp(buf, vbuf, srcsize));
		free(vbuf);
	}
#endif
	BUG_ON(fwrite(out, outsize, 1, stdout) != 1);
	return 0;
}
#endif
