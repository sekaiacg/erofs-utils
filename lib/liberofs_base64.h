#ifndef __EROFS_LIB_LIBEROFS_BASE64_H
#define __EROFS_LIB_LIBEROFS_BASE64_H

#include "erofs/defs.h"

int erofs_base64_encode(const u8 *src, int srclen, char *dst);
int erofs_base64_decode(const char *src, int len, u8 *dst);

#endif
