/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2025 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Yifan Zhao <zhaoyifan28@huawei.com>
 */
#ifndef __EROFS_S3_H
#define __EROFS_S3_H

#ifdef __cplusplus
extern "C" {
#endif

enum s3erofs_url_style {
	S3EROFS_URL_STYLE_PATH,          // Path style: https://s3.amazonaws.com/bucket/object
	S3EROFS_URL_STYLE_VIRTUAL_HOST,  // Virtual host style: https://bucket.s3.amazonaws.com/object
};

enum s3erofs_signature_version {
	S3EROFS_SIGNATURE_VERSION_2,
	S3EROFS_SIGNATURE_VERSION_4,
};

#define S3_ACCESS_KEY_LEN 256
#define S3_SECRET_KEY_LEN 256

struct erofs_s3 {
	const char *endpoint;
	char access_key[S3_ACCESS_KEY_LEN + 1];
	char secret_key[S3_SECRET_KEY_LEN + 1];

	enum s3erofs_url_style url_style;
	enum s3erofs_signature_version sig;
};

int s3erofs_build_trees(struct erofs_inode *root, struct erofs_s3 *s3,
			const char *path, bool fillzero);

#ifdef __cplusplus
}
#endif

#endif
