/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
#ifndef __EROFS_LIB_UUID_H
#define __EROFS_LIB_UUID_H

#ifdef __cplusplus
extern "C"
{
#endif

void erofs_uuid_generate(unsigned char *out);
void erofs_uuid_unparse_lower(const unsigned char *buf, char *out);
int erofs_uuid_parse(const char *in, unsigned char *uu);

#ifdef __cplusplus
}
#endif

#endif
