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

struct erofs_inode;
struct CURL;
struct erofs_importer;

/**
 * struct erofs_oci_params - OCI configuration parameters
 * @registry: registry hostname (e.g., "registry-1.docker.io")
 * @repository: image repository (e.g., "library/ubuntu")
 * @tag: image tag or digest (e.g., "latest" or sha256:...)
 * @platform: target platform in "os/arch" format (e.g., "linux/amd64")
 * @username: username for authentication (optional)
 * @password: password for authentication (optional)
 * @layer_index: specific layer to extract (-1 for all layers)
 *
 * Configuration structure for OCI image parameters including registry
 * location, image identification, platform specification, and authentication
 * credentials.
 */
struct erofs_oci_params {
	char *registry;
	char *repository;
	char *tag;
	char *platform;
	char *username;
	char *password;
	int layer_index;
};

/**
 * struct erofs_oci - Combined OCI client structure
 * @curl: CURL handle for HTTP requests
 * @params: OCI configuration parameters
 *
 * Main OCI client structure combining CURL HTTP client with
 * OCI-specific configuration parameters.
 */
struct erofs_oci {
	struct CURL *curl;
	struct erofs_oci_params params;
};

/*
 * ocierofs_init - Initialize OCI client with default parameters
 * @oci: OCI client structure to initialize
 *
 * Return: 0 on success, negative errno on failure
 */
int ocierofs_init(struct erofs_oci *oci);

/*
 * ocierofs_cleanup - Clean up OCI client and free allocated resources
 * @oci: OCI client structure to clean up
 */
void ocierofs_cleanup(struct erofs_oci *oci);

/*
 * erofs_oci_params_set_string - Set a string field with dynamic allocation
 * @field: pointer to the string field to set
 * @value: string value to set
 *
 * Return: 0 on success, negative errno on failure
 */
int erofs_oci_params_set_string(char **field, const char *value);

/*
 * ocierofs_parse_ref - Parse OCI image reference string
 * @oci: OCI client structure
 * @ref_str: OCI image reference string
 *
 * Return: 0 on success, negative errno on failure
 */
int ocierofs_parse_ref(struct erofs_oci *oci, const char *ref_str);

/*
 * ocierofs_build_trees - Build file trees from OCI container image layers
 * @root:     root inode to build the file tree under
 * @oci:      OCI client structure with configured parameters
 *
 * Return: 0 on success, negative errno on failure
 */
int ocierofs_build_trees(struct erofs_importer *importer, struct erofs_oci *oci);

#ifdef __cplusplus
}
#endif

#endif /* __EROFS_OCI_H */
