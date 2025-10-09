/* SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0 */
/*
 * Copyright (C) 2025 Tencent, Inc.
 *             http://www.tencent.com/
 */
#ifndef __EROFS_OCI_H
#define __EROFS_OCI_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct CURL;
struct erofs_importer;

/*
 * struct ocierofs_config - OCI configuration structure
 * @image_ref: OCI image reference (e.g., "ubuntu:latest", "myregistry.com/app:v1.0")
 * @platform: target platform in "os/arch" format (e.g., "linux/amd64")
 * @username: username for authentication (optional)
 * @password: password for authentication (optional)
 * @blob_digest: specific blob digest to extract (NULL for all layers)
 * @layer_index: specific layer index to extract (negative for all layers)
 *
 * Configuration structure for OCI image parameters including registry
 * location, image identification, platform specification, and authentication
 * credentials.
 */
struct ocierofs_config {
	char *image_ref;
	char *platform;
	char *username;
	char *password;
	char *blob_digest;
	int layer_index;
	char *tarindex_path;
	char *zinfo_path;
};

struct ocierofs_layer_info {
	char *digest;
	char *media_type;
	u64 size;
};

struct ocierofs_ctx {
	struct CURL *curl;
	char *auth_header;
	bool using_basic;
	char *registry;
	char *repository;
	char *platform;
	char *tag;
	char *manifest_digest;
	struct ocierofs_layer_info **layers;
	char *blob_digest;
	int layer_count;
};

struct ocierofs_iostream {
	struct ocierofs_ctx *ctx;
	u64 offset;
};

/*
 * ocierofs_build_trees - Build file trees from OCI container image layers
 * @importer: erofs importer to populate
 * @cfg:      oci configuration
 *
 * Return: 0 on success, negative errno on failure
 */
int ocierofs_build_trees(struct erofs_importer *importer,
			 const struct ocierofs_config *cfg);
int ocierofs_io_open(struct erofs_vfile *vf, const struct ocierofs_config *cfg);

char *ocierofs_encode_userpass(const char *username, const char *password);
int ocierofs_decode_userpass(const char *b64, char **out_user, char **out_pass);

#ifdef __cplusplus
}
#endif

#endif /* __EROFS_OCI_H */
