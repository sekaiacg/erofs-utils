// SPDX-License-Identifier: Unlicense
/*
 * sha256.c --- The sha256 algorithm
 *
 * (copied from LibTomCrypt with adaption.)
 */
#include "sha256.h"
#include <string.h>

#ifdef __USE_OPENSSL_SHA256
void erofs_sha256_init(struct sha256_state *md)
{
	int ret;

	md->ctx = EVP_MD_CTX_new();
	if (!md->ctx)
		return;
	ret = EVP_DigestInit(md->ctx, EVP_sha256());
	DBG_BUGON(ret != 1);
}

int erofs_sha256_process(struct sha256_state *md,
		const unsigned char *in, unsigned long inlen)
{
	int ret;

	if (!md->ctx)
		return -1;
	ret = EVP_DigestUpdate(md->ctx, in, inlen);
	return (ret == 1) - 1;
}

int erofs_sha256_done(struct sha256_state *md, unsigned char *out)
{
	int ret;
	unsigned int mdsize;

	if (!md->ctx)
		return -1;
	ret = EVP_DigestFinal_ex(md->ctx, out, &mdsize);
	if (ret != 1)
		return -1;
	EVP_MD_CTX_free(md->ctx);
	return 0;
}
#else
/* This is based on SHA256 implementation in LibTomCrypt that was released into
 * public domain by Tom St Denis. */
/* the K array */
static const unsigned long K[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
	0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
	0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
	0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
	0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
	0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
	0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
	0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
	0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
	0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};
/* Various logical functions */
#define RORc(x, y) \
( ((((unsigned long) (x) & 0xFFFFFFFFUL) >> (unsigned long) ((y) & 31)) | \
   ((unsigned long) (x) << (unsigned long) (32 - ((y) & 31)))) & 0xFFFFFFFFUL)
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         RORc((x), (n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))
#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#define STORE64H(x, y) \
	do { \
		(y)[0] = (unsigned char)(((x)>>56)&255);\
		(y)[1] = (unsigned char)(((x)>>48)&255);\
		(y)[2] = (unsigned char)(((x)>>40)&255);\
		(y)[3] = (unsigned char)(((x)>>32)&255);\
		(y)[4] = (unsigned char)(((x)>>24)&255);\
		(y)[5] = (unsigned char)(((x)>>16)&255);\
		(y)[6] = (unsigned char)(((x)>>8)&255);\
		(y)[7] = (unsigned char)((x)&255); } while(0)

#define STORE32H(x, y)                                                                     \
  do { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); } while(0)

#define LOAD32H(x, y)                            \
  do { x = ((u32)((y)[0] & 255)<<24) | \
           ((u32)((y)[1] & 255)<<16) | \
           ((u32)((y)[2] & 255)<<8)  | \
           ((u32)((y)[3] & 255)); } while(0)

/* compress 512-bits */
static int sha256_compress(struct sha256_state *md, unsigned char *buf)
{
	u32 S[8], W[64], t0, t1;
	u32 t;
	int i;
	/* copy state into S */
	for (i = 0; i < 8; i++) {
		S[i] = md->state[i];
	}
	/* copy the state into 512-bits into W[0..15] */
	for (i = 0; i < 16; i++)
		LOAD32H(W[i], buf + (4 * i));
	/* fill W[16..63] */
	for (i = 16; i < 64; i++) {
		W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) +
			W[i - 16];
	}
	/* Compress */
#define RND(a,b,c,d,e,f,g,h,i)                          \
	t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];	\
	t1 = Sigma0(a) + Maj(a, b, c);			\
	d += t0;					\
	h  = t0 + t1;
	for (i = 0; i < 64; ++i) {
		RND(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i);
		t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4];
		S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
	}
	/* feedback */
	for (i = 0; i < 8; i++) {
		md->state[i] = md->state[i] + S[i];
	}
	return 0;
}
/* Initialize the hash state */
void erofs_sha256_init(struct sha256_state *md)
{
	md->curlen = 0;
	md->length = 0;
	md->state[0] = 0x6A09E667UL;
	md->state[1] = 0xBB67AE85UL;
	md->state[2] = 0x3C6EF372UL;
	md->state[3] = 0xA54FF53AUL;
	md->state[4] = 0x510E527FUL;
	md->state[5] = 0x9B05688CUL;
	md->state[6] = 0x1F83D9ABUL;
	md->state[7] = 0x5BE0CD19UL;
}
/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int erofs_sha256_process(struct sha256_state *md,
		const unsigned char *in, unsigned long inlen)
{
	unsigned long n;
#define block_size 64
	if (md->curlen > sizeof(md->buf))
		return -1;
	while (inlen > 0) {
		if (md->curlen == 0 && inlen >= block_size) {
			if (sha256_compress(md, (unsigned char *) in) < 0)
				return -1;
			md->length += block_size * 8;
			in += block_size;
			inlen -= block_size;
		} else {
			n = MIN(inlen, (block_size - md->curlen));
			memcpy(md->buf + md->curlen, in, n);
			md->curlen += n;
			in += n;
			inlen -= n;
			if (md->curlen == block_size) {
				if (sha256_compress(md, md->buf) < 0)
					return -1;
				md->length += 8 * block_size;
				md->curlen = 0;
			}
		}
	}
	return 0;
}
/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (32 bytes)
   @return CRYPT_OK if successful
*/
int erofs_sha256_done(struct sha256_state *md, unsigned char *out)
{
	int i;
	if (md->curlen >= sizeof(md->buf))
		return -1;
	/* increase the length of the message */
	md->length += md->curlen * 8;
	/* append the '1' bit */
	md->buf[md->curlen++] = (unsigned char) 0x80;
	/* if the length is currently above 56 bytes we append zeros
	 * then compress.  Then we can fall back to padding zeros and length
	 * encoding like normal.
	 */
	if (md->curlen > 56) {
		while (md->curlen < 64) {
			md->buf[md->curlen++] = (unsigned char) 0;
		}
		sha256_compress(md, md->buf);
		md->curlen = 0;
	}
	/* pad upto 56 bytes of zeroes */
	while (md->curlen < 56) {
		md->buf[md->curlen++] = (unsigned char) 0;
	}
	/* store length */
	STORE64H(md->length, md->buf+56);
	sha256_compress(md, md->buf);
	/* copy output */
	for (i = 0; i < 8; i++)
		STORE32H(md->state[i], out + (4 * i));
	return 0;
}
#endif

void erofs_sha256(const unsigned char *in, unsigned long in_size,
		  unsigned char out[32])
{
	struct sha256_state md;

	erofs_sha256_init(&md);
#ifdef __USE_OPENSSL_SHA256
	EVP_MD_CTX_set_flags(md.ctx, EVP_MD_CTX_FLAG_ONESHOT);
#endif
	erofs_sha256_process(&md, in, in_size);
	erofs_sha256_done(&md, out);
}

#ifdef UNITTEST
#include <stdio.h>

static const struct {
	char *msg;
	unsigned char hash[32];
} tests[] = {
	{ "",
	  { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 }
	},
	{ "abc",
	  { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
	    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
	    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
	    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad }
	},
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
	    0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
	    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
	    0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 }
	},
};

int main(int argc, char **argv)
{
	int i;
	int errors = 0;
	unsigned char tmp[32];

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		unsigned char *msg = (unsigned char *) tests[i].msg;
		int len = strlen(tests[i].msg);

		erofs_sha256(msg, len, tmp);
		printf("SHA256 test message %d: ", i);
		if (memcmp(tmp, tests[i].hash, 32) != 0) {
			printf("FAILED\n");
			errors++;
		} else
			printf("OK\n");
	}
	return errors;
}

#endif /* UNITTEST */
