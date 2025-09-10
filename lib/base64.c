// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
#include "liberofs_base64.h"
#include <string.h>

static const char lookup_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int erofs_base64_encode(const u8 *src, int srclen, char *dst)
{
        u32 ac = 0;
        int bits = 0;
        int i;
        char *cp = dst;

        for (i = 0; i < srclen; i++) {
                ac = (ac << 8) | src[i];
                bits += 8;
                do {
                        bits -= 6;
                        *cp++ = lookup_table[(ac >> bits) & 0x3f];
                } while (bits >= 6);
        }
        if (bits) {
                *cp++ = lookup_table[(ac << (6 - bits)) & 0x3f];
                bits -= 6;
        }
        while (bits < 0) {
                *cp++ = '=';
                bits += 2;
        }
        return cp - dst;
}

int erofs_base64_decode(const char *src, int len, u8 *dst)
{
	int i, bits = 0, ac = 0;
	const char *p;
	u8 *cp = dst;
	bool padding = false;

	if(len && !(len % 4)) {
		/* Check for and ignore any end padding */
		if (src[len - 1] == '=')
			len -= 1 + (len >= 2 && src[len - 2] == '=');
		padding = true;
	}

	for (i = 0; i < len; i++) {
		p = strchr(lookup_table, src[i]);
		if (!p || !src[i])
			return -2;
		ac = (ac << 6 | (p - lookup_table));
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*cp++ = ac >> bits;
		}
	}
	ac &= BIT(bits) - 1;
	if (ac) {
		if (padding || ac > 0xff)
			return -1;
		else
			*cp++ = ac;
	}
	return cp - dst;
}
