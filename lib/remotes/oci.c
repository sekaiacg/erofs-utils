// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2025 Tencent, Inc.
 *             http://www.tencent.com/
 */
#define _GNU_SOURCE
#include "erofs/internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef HAVE_CURL_CURL_H
#include <curl/curl.h>
#endif
#ifdef HAVE_JSON_C_JSON_H
#include <json-c/json.h>
#endif
#include "erofs/importer.h"
#include "erofs/internal.h"
#include "erofs/io.h"
#include "erofs/print.h"
#include "erofs/tar.h"
#include "liberofs_oci.h"
#include "liberofs_private.h"

#ifdef OCIEROFS_ENABLED

#define DOCKER_REGISTRY "docker.io"
#define DOCKER_API_REGISTRY "registry-1.docker.io"

#define DOCKER_MEDIATYPE_MANIFEST_V2 \
	"application/vnd.docker.distribution.manifest.v2+json"
#define DOCKER_MEDIATYPE_MANIFEST_V1 \
	"application/vnd.docker.distribution.manifest.v1+json"
#define DOCKER_MEDIATYPE_MANIFEST_LIST \
	"application/vnd.docker.distribution.manifest.list.v2+json"
#define OCI_MEDIATYPE_MANIFEST "application/vnd.oci.image.manifest.v1+json"
#define OCI_MEDIATYPE_INDEX "application/vnd.oci.image.index.v1+json"

#define OCIEROFS_IO_CHUNK_SIZE 32768

struct ocierofs_request {
	char *url;
	struct curl_slist *headers;
};

struct ocierofs_response {
	char *data;
	size_t size;
	long http_code;
};

struct ocierofs_stream {
	const char *digest;
	int blobfd;
};

static inline const char *ocierofs_get_api_registry(const char *registry)
{
	if (!registry)
		return DOCKER_API_REGISTRY;
	return !strcmp(registry, DOCKER_REGISTRY) ? DOCKER_API_REGISTRY : registry;
}

static inline bool ocierofs_is_manifest(const char *media_type)
{
	return media_type && (!strcmp(media_type, DOCKER_MEDIATYPE_MANIFEST_V2) ||
			       !strcmp(media_type, OCI_MEDIATYPE_MANIFEST));
}

static inline void ocierofs_request_cleanup(struct ocierofs_request *req)
{
	if (!req)
		return;
	if (req->headers)
		curl_slist_free_all(req->headers);
	free(req->url);
	req->url = NULL;
	req->headers = NULL;
}

static inline void ocierofs_response_cleanup(struct ocierofs_response *resp)
{
	if (!resp)
		return;
	free(resp->data);
	resp->data = NULL;
	resp->size = 0;
	resp->http_code = 0;
}

static size_t ocierofs_write_callback(void *contents, size_t size,
				      size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct ocierofs_response *resp = userp;
	char *ptr;

	if (!resp->data)
		resp->size = 0;

	ptr = realloc(resp->data, resp->size + realsize + 1);
	if (!ptr) {
		erofs_err("failed to allocate memory for response data");
		return 0;
	}
	resp->data = ptr;
	memcpy(&resp->data[resp->size], contents, realsize);
	resp->size += realsize;
	resp->data[resp->size] = '\0';
	return realsize;
}

static size_t ocierofs_layer_write_callback(void *contents, size_t size,
					    size_t nmemb, void *userp)
{
	struct ocierofs_stream *stream = userp;
	size_t realsize = size * nmemb;
	const char *buf = contents;
	size_t written = 0;

	if (stream->blobfd < 0)
		return 0;

	while (written < realsize) {
		ssize_t n = write(stream->blobfd, buf + written, realsize - written);

		if (n < 0) {
			erofs_err("failed to write layer data for layer %s",
				  stream->digest);
			return 0;
		}
		written += n;
	}
	return realsize;
}

static int ocierofs_curl_setup_common_options(struct CURL *curl)
{
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "ocierofs/" PACKAGE_VERSION);
	curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
#if defined(CURLOPT_TCP_KEEPIDLE)
	curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 30L);
#endif
#if defined(CURLOPT_TCP_KEEPINTVL)
	curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 15L);
#endif
	return 0;
}

static int ocierofs_curl_setup_basic_auth(struct CURL *curl, const char *username,
					  const char *password)
{
	char *userpwd;

	if (asprintf(&userpwd, "%s:%s", username, password) == -1)
		return -ENOMEM;

	curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

	free(userpwd);
	return 0;
}

static int ocierofs_curl_clear_auth(struct ocierofs_ctx *ctx)
{
	curl_easy_setopt(ctx->curl, CURLOPT_USERPWD, NULL);
	curl_easy_setopt(ctx->curl, CURLOPT_HTTPAUTH, CURLAUTH_NONE);
	return 0;
}

enum ocierofs_http_method { OCIEROFS_HTTP_GET, OCIEROFS_HTTP_HEAD };

static int ocierofs_curl_setup_rq(struct CURL *curl, const char *url,
				  enum ocierofs_http_method method,
				  struct curl_slist *headers,
				  size_t (*write_func)(void *, size_t, size_t, void *),
				  void *write_data,
				  size_t (*header_func)(void *, size_t, size_t, void *),
				  void *header_data)
{
	curl_easy_setopt(curl, CURLOPT_URL, url);

	if (method == OCIEROFS_HTTP_HEAD) {
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	} else {
		curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
		curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
	}

	if (write_func) {
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, write_data);
	}

	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_func);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, header_data);

	if (headers)
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	return 0;
}

static int ocierofs_curl_perform(struct CURL *curl, long *http_code_out)
{
	CURLcode res;
	long http_code = 0;

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		erofs_err("curl request failed: %s", curl_easy_strerror(res));
		return -EIO;
	}

	if (http_code_out) {
		res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (res != CURLE_OK) {
			erofs_err("failed to get HTTP response code: %s",
				  curl_easy_strerror(res));
			return -EIO;
		}
		*http_code_out = http_code;
	}
	return 0;
}

static int ocierofs_request_perform(struct ocierofs_ctx *ctx,
				    struct ocierofs_request *req,
				    struct ocierofs_response *resp)
{
	int ret;

	ret = ocierofs_curl_setup_rq(ctx->curl, req->url,
				     OCIEROFS_HTTP_GET, req->headers,
			             ocierofs_write_callback, resp,
				     NULL, NULL);
	if (ret)
		return ret;

	ret = ocierofs_curl_perform(ctx->curl, &resp->http_code);
	if (ret)
		return ret;

	if (resp->http_code < 200 || resp->http_code >= 300)
		return -EIO;
	return 0;
}

/**
 * ocierofs_parse_auth_header - Parse WWW-Authenticate header for Bearer auth
 * @auth_header: authentication header string
 * @realm_out: pointer to store realm value
 * @service_out: pointer to store service value
 * @scope_out: pointer to store scope value
 *
 * Parse Bearer authentication header and extract realm, service, and scope
 * parameters for subsequent token requests.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ocierofs_parse_auth_header(const char *auth_header,
				      char **realm_out, char **service_out,
				      char **scope_out)
{
	char *realm = NULL, *service = NULL, *scope = NULL;
	static const char * const param_names[] = {"realm=", "service=", "scope="};
	char **param_values[] = {&realm, &service, &scope};
	char *header_copy = NULL;
	const char *p;
	int i, ret = 0;

	// https://datatracker.ietf.org/doc/html/rfc6750#section-3
	if (strncmp(auth_header, "Bearer ", strlen("Bearer ")))
		return -EINVAL;

	header_copy = strdup(auth_header);
	if (!header_copy)
		return -ENOMEM;

	/* Clean up header: replace newlines with spaces and remove double spaces */
	for (char *q = header_copy; *q; q++) {
		if (*q == '\n' || *q == '\r')
			*q = ' ';
	}

	p = header_copy + strlen("Bearer ");
	for (i = 0; i < ARRAY_SIZE(param_names); i++) {
		const char *param_start;
		char *value;
		size_t len;

		param_start = strstr(p, param_names[i]);
		if (!param_start)
			continue;

		param_start += strlen(param_names[i]);
		if (*param_start != '"')
			continue;

		param_start++;
		const char *param_end = strchr(param_start, '"');

		if (!param_end)
			continue;

		len = param_end - param_start;
		value = strndup(param_start, len);
		if (!value) {
			ret = -ENOMEM;
			goto out;
		}
		*param_values[i] = value;
	}

	free(header_copy);
	*realm_out = realm;
	*service_out = service;
	*scope_out = scope;
	return 0;
out:
	free(header_copy);
	free(realm);
	free(service);
	free(scope);
	return ret;
}

/**
 * ocierofs_extract_www_auth_info - Extract WWW-Authenticate header information
 * @resp_data: HTTP response data containing headers
 * @realm_out: pointer to store realm value (optional)
 * @service_out: pointer to store service value (optional)
 * @scope_out: pointer to store scope value (optional)
 *
 * Extract realm, service, and scope from WWW-Authenticate header in HTTP response.
 * This function handles the common pattern of parsing WWW-Authenticate headers
 * that appears in multiple places in the OCI authentication flow.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ocierofs_extract_www_auth_info(const char *resp_data,
					  char **realm_out, char **service_out,
					  char **scope_out)
{
	char *www_auth;
	char *line_end;
	char *realm = NULL, *service = NULL, *scope = NULL;
	int ret;

	if (!resp_data)
		return -EINVAL;

	www_auth = strcasestr(resp_data, "www-authenticate:");
	if (!www_auth)
		return -ENOENT;

	line_end = strchr(www_auth, '\n');
	if (line_end)
		*line_end = '\0';

	www_auth += strlen("www-authenticate:");
	while (*www_auth == ' ')
		www_auth++;

	ret = ocierofs_parse_auth_header(www_auth, &realm, &service, &scope);
	if (ret == 0) {
		if (realm_out) {
			*realm_out = realm;
			realm = NULL;
		}
		if (service_out) {
			*service_out = service;
			service = NULL;
		}
		if (scope_out) {
			*scope_out = scope;
			scope = NULL;
		}
	}

	free(realm);
	free(service);
	free(scope);
	return ret;
}

/**
 * ocierofs_get_auth_token_with_url - Get authentication token from auth server
 * @ctx: OCI context structure
 * @auth_url: authentication server URL
 * @service: service name for authentication
 * @repository: repository name
 * @username: username for basic auth (optional)
 * @password: password for basic auth (optional)
 *
 * Request authentication token from the specified auth server URL using
 * basic authentication if credentials are provided.
 *
 * Return: authentication header string on success, ERR_PTR on failure
 */
static char *ocierofs_get_auth_token_with_url(struct ocierofs_ctx *ctx, const char *auth_url,
					      const char *service, const char *repository,
					      const char *username, const char *password)
{
	struct ocierofs_request req = {};
	struct ocierofs_response resp = {};
	json_object *root, *token_obj, *access_token_obj;
	const char *token;
	char *auth_header = NULL;
	int ret;

	if (!auth_url || !service || !repository)
		return ERR_PTR(-EINVAL);

	if (asprintf(&req.url, "%s?service=%s&scope=repository:%s:pull",
		     auth_url, service, repository) == -1) {
		return ERR_PTR(-ENOMEM);
	}

	if (username && password && *username) {
		ret = ocierofs_curl_setup_basic_auth(ctx->curl, username,
						     password);
		if (ret)
			goto out_url;
	}

	ret = ocierofs_request_perform(ctx, &req, &resp);
	ocierofs_curl_clear_auth(ctx);
	if (ret)
		goto out_url;

	if (!resp.data) {
		erofs_err("empty response from auth server");
		ret = -EINVAL;
		goto out_url;
	}

	root = json_tokener_parse(resp.data);
	if (!root) {
		erofs_err("failed to parse auth response");
		ret = -EINVAL;
		goto out_json;
	}

	if (!json_object_object_get_ex(root, "token", &token_obj) &&
	    !json_object_object_get_ex(root, "access_token", &access_token_obj)) {
		erofs_err("no token found in auth response");
		ret = -EINVAL;
		goto out_json;
	}

	token = json_object_get_string(token_obj ? token_obj : access_token_obj);
	if (!token) {
		erofs_err("invalid token in auth response");
		ret = -EINVAL;
		goto out_json;
	}

	if (asprintf(&auth_header, "Authorization: Bearer %s", token) == -1) {
		ret = -ENOMEM;
		goto out_json;
	}

out_json:
	json_object_put(root);
out_url:
	ocierofs_response_cleanup(&resp);
	ocierofs_request_cleanup(&req);
	return ret ? ERR_PTR(ret) : auth_header;
}

static char *ocierofs_discover_auth_endpoint(struct ocierofs_ctx *ctx,
					     const char *registry,
					     const char *repository)
{
	struct ocierofs_response resp = {};
	char *realm = NULL;
	char *service = NULL;
	char *result = NULL;
	char *test_url;
	const char *api_registry;
	CURLcode res;
	long http_code;

	api_registry = ocierofs_get_api_registry(registry);

	if (asprintf(&test_url, "https://%s/v2/%s/manifests/nonexistent",
	     api_registry, repository) < 0)
		return NULL;

	curl_easy_reset(ctx->curl);
	ocierofs_curl_setup_common_options(ctx->curl);

	ocierofs_curl_setup_rq(ctx->curl, test_url, OCIEROFS_HTTP_HEAD, NULL,
			       NULL, NULL, ocierofs_write_callback, &resp);

	res = curl_easy_perform(ctx->curl);
	curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

	if (res == CURLE_OK && (http_code == 401 || http_code == 403 ||
	    http_code == 404) && resp.data) {
		if (ocierofs_extract_www_auth_info(resp.data, &realm, &service, NULL) == 0) {
			result = realm;
			realm = NULL;
		}
	}
	free(realm);
	free(service);
	ocierofs_response_cleanup(&resp);
	free(test_url);
	return result;
}

static char *ocierofs_get_auth_token(struct ocierofs_ctx *ctx, const char *registry,
				     const char *repository, const char *username,
				     const char *password)
{
	static const char * const auth_patterns[] = {
		"https://%s/v2/auth",
		"https://auth.%s/token",
		"https://%s/token",
		NULL,
	};
	char *auth_header = NULL;
	char *discovered_auth_url = NULL;
	char *discovered_service = NULL;
	const char *service = registry;
	bool docker_reg;
	int i;

	docker_reg = !strcmp(registry, DOCKER_API_REGISTRY) ||
		!strcmp(registry, DOCKER_REGISTRY);
	if (docker_reg) {
		service = "registry.docker.io";
		auth_header = ocierofs_get_auth_token_with_url(ctx,
				"https://auth.docker.io/token", service, repository,
				username, password);
		if (!IS_ERR(auth_header))
			return auth_header;
	}

	discovered_auth_url = ocierofs_discover_auth_endpoint(ctx, registry, repository);
	if (discovered_auth_url) {
		const char *api_registry, *auth_service;
		struct ocierofs_response resp = {};
		char *test_url;
		CURLcode res;
		long http_code;

		api_registry = ocierofs_get_api_registry(registry);

		if (asprintf(&test_url, "https://%s/v2/%s/manifests/nonexistent",
		     api_registry, repository) >= 0) {
			curl_easy_reset(ctx->curl);
			ocierofs_curl_setup_common_options(ctx->curl);

			ocierofs_curl_setup_rq(ctx->curl, test_url,
					       OCIEROFS_HTTP_HEAD, NULL,
					       NULL, NULL,
					       ocierofs_write_callback, &resp);

			res = curl_easy_perform(ctx->curl);
			curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &http_code);

			if (res == CURLE_OK && (http_code == 401 || http_code == 403 ||
			    http_code == 404) && resp.data) {
				char *realm = NULL;

				ocierofs_extract_www_auth_info(resp.data, &realm, &discovered_service, NULL);
				free(realm);
			}
			ocierofs_response_cleanup(&resp);
			free(test_url);
		}

		auth_service = discovered_service ? discovered_service : service;
		auth_header = ocierofs_get_auth_token_with_url(ctx, discovered_auth_url,
							       auth_service, repository,
							       username, password);
		free(discovered_auth_url);
		free(discovered_service);
		if (!IS_ERR(auth_header))
			return auth_header;
	}

	for (i = 0; auth_patterns[i]; i++) {
		char *auth_url;

		if (asprintf(&auth_url, auth_patterns[i], registry) < 0)
			continue;

		auth_header = ocierofs_get_auth_token_with_url(ctx, auth_url,
							       service, repository,
							       username, password);
		free(auth_url);

		if (!IS_ERR(auth_header))
			return auth_header;
		if (!docker_reg)
			return NULL;
	}
	return ERR_PTR(-ENOENT);
}

static char *ocierofs_get_manifest_digest(struct ocierofs_ctx *ctx,
					  const char *registry,
					  const char *repository, const char *tag,
					  const char *platform,
					  const char *auth_header)
{
	struct ocierofs_request req = {};
	struct ocierofs_response resp = {};
	json_object *root, *manifests, *manifest, *platform_obj, *arch_obj;
	json_object *os_obj, *digest_obj, *schema_obj, *media_type_obj;
	char *digest = NULL;
	const char *api_registry;
	int ret = 0, len, i;

	api_registry = ocierofs_get_api_registry(registry);
	if (asprintf(&req.url, "https://%s/v2/%s/manifests/%s",
	     api_registry, repository, tag) < 0)
		return ERR_PTR(-ENOMEM);

	if (auth_header && strstr(auth_header, "Bearer"))
		req.headers = curl_slist_append(req.headers, auth_header);

	req.headers = curl_slist_append(req.headers,
		"Accept: " DOCKER_MEDIATYPE_MANIFEST_LIST ","
		OCI_MEDIATYPE_INDEX "," OCI_MEDIATYPE_MANIFEST ","
		DOCKER_MEDIATYPE_MANIFEST_V1 "," DOCKER_MEDIATYPE_MANIFEST_V2);

	ret = ocierofs_request_perform(ctx, &req, &resp);
	if (ret)
		goto out;

	if (!resp.data) {
		erofs_err("empty response from manifest request");
		ret = -EINVAL;
		goto out;
	}

	root = json_tokener_parse(resp.data);
	if (!root) {
		erofs_err("failed to parse manifest JSON");
		ret = -EINVAL;
		goto out;
	}

	if (json_object_object_get_ex(root, "schemaVersion", &schema_obj)) {
		if (json_object_get_int(schema_obj) < 0) {
			digest = strdup(tag);
			ret = 0;
			goto out_json;
		}
	}

	if (json_object_object_get_ex(root, "mediaType", &media_type_obj)) {
		const char *media_type = json_object_get_string(media_type_obj);

		if (ocierofs_is_manifest(media_type)) {
			digest = strdup(tag);
			ret = 0;
			goto out_json;
		}
	}

	if (!json_object_object_get_ex(root, "manifests", &manifests)) {
		erofs_err("no manifests found in manifest list");
		ret = -EINVAL;
		goto out_json;
	}

	len = json_object_array_length(manifests);
	for (i = 0; i < len; i++) {
		manifest = json_object_array_get_idx(manifests, i);

		if (json_object_object_get_ex(manifest, "platform",
					      &platform_obj) &&
		    json_object_object_get_ex(platform_obj, "architecture",
					      &arch_obj) &&
		    json_object_object_get_ex(platform_obj, "os", &os_obj) &&
		    json_object_object_get_ex(manifest, "digest", &digest_obj)) {
			const char *arch = json_object_get_string(arch_obj);
			const char *os = json_object_get_string(os_obj);
			char manifest_platform[64];

			snprintf(manifest_platform, sizeof(manifest_platform),
				 "%s/%s", os, arch);
			if (!strcmp(manifest_platform, platform)) {
				digest = strdup(json_object_get_string(digest_obj));
				break;
			}
		}
	}

	if (!digest)
		ret = -ENOENT;

out_json:
	json_object_put(root);
out:
	ocierofs_response_cleanup(&resp);
	ocierofs_request_cleanup(&req);
	return ret ? ERR_PTR(ret) : digest;
}

static void ocierofs_free_layers_info(struct ocierofs_layer_info **layers, int count)
{
	int i;

	if (!layers)
		return;

	for (i = 0; i < count; i++) {
		if (layers[i]) {
			free(layers[i]->digest);
			free(layers[i]->media_type);
			free(layers[i]);
		}
	}
	free(layers);
}

static int ocierofs_fetch_layers_info(struct ocierofs_ctx *ctx)
{
	const char *registry = ctx->registry;
	const char *repository = ctx->repository;
	const char *digest = ctx->manifest_digest;
	const char *auth_header = ctx->auth_header;
	struct ocierofs_request req = {};
	struct ocierofs_response resp = {};
	json_object *root, *layers, *layer, *digest_obj, *media_type_obj, *size_obj;
	struct ocierofs_layer_info **layers_info = NULL;
	const char *api_registry;
	int ret, len, i;

	ctx->layer_count = 0;
	api_registry = ocierofs_get_api_registry(registry);

	if (asprintf(&req.url, "https://%s/v2/%s/manifests/%s",
		     api_registry, repository, digest) < 0)
		return -ENOMEM;

	if (auth_header && strstr(auth_header, "Bearer"))
		req.headers = curl_slist_append(req.headers, auth_header);

	req.headers = curl_slist_append(req.headers,
			"Accept: " OCI_MEDIATYPE_MANIFEST "," DOCKER_MEDIATYPE_MANIFEST_V2);

	ret = ocierofs_request_perform(ctx, &req, &resp);
	if (ret)
		goto out;

	if (!resp.data) {
		erofs_err("empty response from layers request");
		ret = -EINVAL;
		goto out;
	}

	root = json_tokener_parse(resp.data);
	if (!root) {
		erofs_err("failed to parse manifest JSON");
		ret = -EINVAL;
		goto out;
	}

	if (!json_object_object_get_ex(root, "layers", &layers) ||
	    json_object_get_type(layers) != json_type_array) {
		erofs_err("no layers found in manifest");
		ret = -EINVAL;
		goto out_json;
	}

	len = json_object_array_length(layers);
	if (!len) {
		ret = -EINVAL;
		goto out_json;
	}

	layers_info = calloc(len, sizeof(*layers_info));
	if (!layers_info) {
		ret = -ENOMEM;
		goto out_json;
	}

	for (i = 0; i < len; i++) {
		layer = json_object_array_get_idx(layers, i);

		if (!json_object_object_get_ex(layer, "digest", &digest_obj)) {
			ret = -EINVAL;
			goto out_free;
		}

		layers_info[i] = calloc(1, sizeof(**layers_info));
		if (!layers_info[i]) {
			ret = -ENOMEM;
			goto out_free;
		}
		layers_info[i]->digest = strdup(json_object_get_string(digest_obj));
		if (!layers_info[i]->digest) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (json_object_object_get_ex(layer, "mediaType", &media_type_obj))
			layers_info[i]->media_type = strdup(json_object_get_string(media_type_obj));
		else
			layers_info[i]->media_type = NULL;

		if (json_object_object_get_ex(layer, "size", &size_obj))
			layers_info[i]->size = json_object_get_int64(size_obj);
		else
			layers_info[i]->size = 0;
	}

	ctx->layer_count = len;
	json_object_put(root);
	ocierofs_response_cleanup(&resp);
	ocierofs_request_cleanup(&req);
	ctx->layers = layers_info;
	return 0;

out_free:
	ocierofs_free_layers_info(layers_info, i);
out_json:
	json_object_put(root);
out:
	ocierofs_response_cleanup(&resp);
	ocierofs_request_cleanup(&req);
	return ret;
}

static int ocierofs_process_tar_stream(struct erofs_importer *importer, int fd)
{
	struct erofs_tarfile tarfile = {};
	int ret;

	init_list_head(&tarfile.global.xattrs);

	ret = erofs_iostream_open(&tarfile.ios, fd, EROFS_IOS_DECODER_GZIP);
	if (ret) {
		erofs_err("failed to initialize tar stream: %s",
			  erofs_strerror(ret));
		return ret;
	}

	do {
		ret = tarerofs_parse_tar(importer, &tarfile);
		/* Continue parsing until end of archive */
	} while (!ret);
	erofs_iostream_close(&tarfile.ios);

	if (ret < 0 && ret != -ENODATA) {
		erofs_err("failed to process tar stream: %s",
			  erofs_strerror(ret));
		return ret;
	}

	return 0;
}

static int ocierofs_prepare_auth(struct ocierofs_ctx *ctx,
				 const char *username,
				 const char *password)
{
	char *auth_header = NULL;
	int ret = 0;

	ctx->using_basic = false;
	free(ctx->auth_header);
	ctx->auth_header = NULL;

	auth_header = ocierofs_get_auth_token(ctx, ctx->registry,
					      ctx->repository,
					      username, password);
	if (!IS_ERR(auth_header)) {
		ctx->auth_header = auth_header;
		return 0;
	}

	if (username && password && *username && *password) {
		ret = ocierofs_curl_setup_basic_auth(ctx->curl,
						    username, password);
		if (ret)
			return ret;
		ctx->using_basic = true;
	}
	return 0;
}

static int ocierofs_prepare_layers(struct ocierofs_ctx *ctx,
				   const struct ocierofs_config *config)
{
	int ret;

	ret = ocierofs_prepare_auth(ctx, config->username, config->password);
	if (ret)
		return ret;

	ctx->manifest_digest = ocierofs_get_manifest_digest(ctx, ctx->registry,
			ctx->repository, ctx->tag, ctx->platform,
			ctx->auth_header);
	if (IS_ERR(ctx->manifest_digest)) {
		ret = PTR_ERR(ctx->manifest_digest);
		erofs_err("failed to get manifest digest: %s",
			  erofs_strerror(ret));
		ctx->manifest_digest = NULL;
		goto out_auth;
	}

	ret = ocierofs_fetch_layers_info(ctx);
	if (ret) {
		erofs_err("failed to get image layers: %s", erofs_strerror(ret));
		ctx->layers = NULL;
		goto out_manifest;
	}

	if (ctx->layer_index >= ctx->layer_count) {
		erofs_err("layer index %d exceeds available layers (%d)",
			  ctx->layer_index, ctx->layer_count);
		ret = -EINVAL;
		goto out_layers;
	}
	return 0;

out_layers:
	free(ctx->layers);
	ctx->layers = NULL;
out_manifest:
	free(ctx->manifest_digest);
	ctx->manifest_digest = NULL;
out_auth:
	free(ctx->auth_header);
	ctx->auth_header = NULL;
	if (ctx->using_basic)
		ocierofs_curl_clear_auth(ctx);
	return ret;
}

/*
 * ocierofs_parse_ref - Parse OCI image reference string
 * @ctx: OCI context structure
 * @ref_str: OCI image reference string
 *
 * Return: 0 on success, negative errno on failure
 */
static int ocierofs_parse_ref(struct ocierofs_ctx *ctx, const char *ref_str)
{
	char *slash, *colon, *dot;
	const char *repo_part;
	size_t len;
	char *tmp;

	if (!ctx || !ref_str)
		return -EINVAL;

	slash = strchr(ref_str, '/');
	if (slash) {
		dot = strchr(ref_str, '.');
		if (dot && dot < slash) {
			len = slash - ref_str;
			tmp = strndup(ref_str, len);
			if (!tmp)
				return -ENOMEM;
			free(ctx->registry);
			ctx->registry = tmp;
			repo_part = slash + 1;
		} else {
			repo_part = ref_str;
		}
	} else {
		repo_part = ref_str;
	}

	colon = strchr(repo_part, ':');
	if (colon) {
		len = colon - repo_part;
		tmp = strndup(repo_part, len);
		if (!tmp)
			return -ENOMEM;

		if (!strchr(tmp, '/') &&
		    (!strcmp(ctx->registry, DOCKER_API_REGISTRY) ||
		     !strcmp(ctx->registry, DOCKER_REGISTRY))) {
			char *full_repo;

			if (asprintf(&full_repo, "library/%s", tmp) == -1) {
				free(tmp);
				return -ENOMEM;
			}
			free(tmp);
			tmp = full_repo;
		}
		free(ctx->repository);
		ctx->repository = tmp;

		free(ctx->tag);
		ctx->tag = strdup(colon + 1);
		if (!ctx->tag)
			return -ENOMEM;
	} else {
		tmp = strdup(repo_part);
		if (!tmp)
			return -ENOMEM;

		if (!strchr(tmp, '/') &&
		    (!strcmp(ctx->registry, DOCKER_API_REGISTRY) ||
		     !strcmp(ctx->registry, DOCKER_REGISTRY))) {

			char *full_repo;

			if (asprintf(&full_repo, "library/%s", tmp) == -1) {
				free(tmp);
				return -ENOMEM;
			}
			free(tmp);
			tmp = full_repo;
		}
		free(ctx->repository);
		ctx->repository = tmp;
	}
	return 0;
}

/**
 * ocierofs_init - Initialize OCI context
 * @ctx: OCI context structure to initialize
 * @config: OCI configuration
 *
 * Initialize OCI context structure, set up CURL handle, and configure
 * default parameters including platform (linux/amd64), registry
 * (registry-1.docker.io), and tag (latest).
 *
 * Return: 0 on success, negative errno on failure
 */
static int ocierofs_init(struct ocierofs_ctx *ctx, const struct ocierofs_config *config)
{
	int ret;

	ctx->curl = curl_easy_init();
	if (!ctx->curl)
		return -EIO;

	if (ocierofs_curl_setup_common_options(ctx->curl))
		return -EIO;

	if (config->layer_index >= 0)
		ctx->layer_index = config->layer_index;
	else
		ctx->layer_index = -1;
	ctx->registry = strdup("registry-1.docker.io");
	ctx->tag = strdup("latest");
	if (config->platform)
		ctx->platform = strdup(config->platform);
	else
		ctx->platform = strdup("linux/amd64");
	if (!ctx->registry || !ctx->tag || !ctx->platform)
		return -ENOMEM;

	ret = ocierofs_parse_ref(ctx, config->image_ref);
	if (ret)
		return ret;

	ret = ocierofs_prepare_layers(ctx, config);
	if (ret)
		return ret;

	return 0;
}

static int ocierofs_download_blob_to_fd(struct ocierofs_ctx *ctx,
					const char *digest,
					const char *auth_header,
					int outfd)
{
	struct ocierofs_request req = {};
	struct ocierofs_stream stream = {};
	const char *api_registry;
	long http_code;
	int ret;

	stream = (struct ocierofs_stream) {
		.digest = digest,
		.blobfd = outfd,
	};

	api_registry = ocierofs_get_api_registry(ctx->registry);
	if (asprintf(&req.url, "https://%s/v2/%s/blobs/%s",
	     api_registry, ctx->repository, digest) == -1)
		return -ENOMEM;

	if (auth_header && strstr(auth_header, "Bearer"))
		req.headers = curl_slist_append(req.headers, auth_header);

	curl_easy_reset(ctx->curl);

	ret = ocierofs_curl_setup_common_options(ctx->curl);
	if (ret)
		goto out;

	ret = ocierofs_curl_setup_rq(ctx->curl, req.url, OCIEROFS_HTTP_GET,
				     req.headers,
				     ocierofs_layer_write_callback,
				     &stream, NULL, NULL);
	if (ret)
		goto out;

	ret = ocierofs_curl_perform(ctx->curl, &http_code);
	if (ret)
		goto out;

	if (http_code < 200 || http_code >= 300) {
		erofs_err("HTTP request failed with code %ld", http_code);
		ret = -EIO;
		goto out;
	}
	ret = 0;
out:
	ocierofs_request_cleanup(&req);
	return ret;
}

static int ocierofs_extract_layer(struct ocierofs_ctx *ctx,
				  const char *digest, const char *auth_header)
{
	struct ocierofs_stream stream = {};
	int ret;

	stream = (struct ocierofs_stream) {
		.digest = digest,
		.blobfd = erofs_tmpfile(),
	};
	if (stream.blobfd < 0) {
		erofs_err("failed to create temporary file for %s", digest);
		return -errno;
	}

	ret = ocierofs_download_blob_to_fd(ctx, digest, auth_header, stream.blobfd);
	if (ret)
		goto out;

	if (lseek(stream.blobfd, 0, SEEK_SET) < 0) {
		erofs_err("failed to seek to beginning of temp file: %s",
			  strerror(errno));
		ret = -errno;
		goto out;
	}

	return stream.blobfd;

out:
	if (stream.blobfd >= 0)
		close(stream.blobfd);
	return ret;
}


/**
 * ocierofs_ctx_cleanup - Clean up OCI context and free allocated resources
 * @ctx: OCI context structure to clean up
 *
 * Clean up CURL handle, free all allocated string parameters, and
 * reset the OCI context structure to a clean state.
 */
static void ocierofs_ctx_cleanup(struct ocierofs_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->curl) {
		curl_easy_cleanup(ctx->curl);
		ctx->curl = NULL;
	}
	free(ctx->auth_header);
	ctx->auth_header = NULL;

	ocierofs_free_layers_info(ctx->layers, ctx->layer_count);
	free(ctx->registry);
	free(ctx->repository);
	free(ctx->tag);
	free(ctx->platform);
	free(ctx->manifest_digest);
}

int ocierofs_build_trees(struct erofs_importer *importer,
			 const struct ocierofs_config *config)
{
	struct ocierofs_ctx ctx = {};
	int ret, i, end, fd;

	ret = ocierofs_init(&ctx, config);
	if (ret) {
		ocierofs_ctx_cleanup(&ctx);
		return ret;
	}

	if (ctx.layer_index >= 0) {
		i = ctx.layer_index;
		end = i + 1;
	} else {
		i = 0;
		end = ctx.layer_count;
	}

	while (i < end) {
		char *trimmed = erofs_trim_for_progressinfo(ctx.layers[i]->digest,
				sizeof("Extracting layer  ...") - 1);
		erofs_update_progressinfo("Extracting layer %d: %s ...", i,
				  trimmed);
		free(trimmed);
		fd = ocierofs_extract_layer(&ctx, ctx.layers[i]->digest,
					    ctx.auth_header);
		if (fd < 0) {
			erofs_err("failed to extract layer %d: %s", i,
				  erofs_strerror(fd));
			break;
		}
		ret = ocierofs_process_tar_stream(importer, fd);
		close(fd);
		if (ret) {
			erofs_err("failed to process tar stream for layer %d: %s", i,
				  erofs_strerror(ret));
			break;
		}
		i++;
	}
	ocierofs_ctx_cleanup(&ctx);
	return ret;
}

static int ocierofs_download_blob_range(struct ocierofs_ctx *ctx, off_t offset, size_t length,
					void **out_buf, size_t *out_size)
{
	struct ocierofs_request req = {};
	struct ocierofs_response resp = {};
	const char *api_registry;
	char rangehdr[64];
	long http_code = 0;
	int ret;
	int index = ctx->layer_index;
	u64 blob_size = ctx->layers[index]->size;
	size_t available;
	size_t copy_size;

	if (offset < 0)
		return -EINVAL;

	if (offset >= blob_size) {
		*out_size = 0;
		return 0;
	}

	if (length && offset + length > blob_size)
		length = (size_t)(blob_size - offset);

	api_registry = ocierofs_get_api_registry(ctx->registry);
	if (asprintf(&req.url, "https://%s/v2/%s/blobs/%s",
	     api_registry, ctx->repository, ctx->layers[index]->digest) == -1)
		return -ENOMEM;

	if (length)
		snprintf(rangehdr, sizeof(rangehdr), "Range: bytes=%lld-%lld",
			 (long long)offset, (long long)(offset + (off_t)length - 1));
	else
		snprintf(rangehdr, sizeof(rangehdr), "Range: bytes=%lld-",
			 (long long)offset);

	if (ctx->auth_header && strstr(ctx->auth_header, "Bearer"))
		req.headers = curl_slist_append(req.headers, ctx->auth_header);
	req.headers = curl_slist_append(req.headers, rangehdr);

	curl_easy_reset(ctx->curl);

	ret = ocierofs_curl_setup_common_options(ctx->curl);
	if (ret)
		goto out;

	ret = ocierofs_curl_setup_rq(ctx->curl, req.url, OCIEROFS_HTTP_GET,
				     req.headers,
				     ocierofs_write_callback,
				     &resp, NULL, NULL);
	if (ret)
		goto out;

	ret = ocierofs_curl_perform(ctx->curl, &http_code);
	if (ret)
		goto out;

	ret = 0;
	if (http_code == 206) {
		*out_buf = resp.data;
		*out_size = resp.size;
		resp.data = NULL;
	} else if (http_code == 200) {
		if (!offset) {
			*out_buf = resp.data;
			*out_size = resp.size;
			resp.data = NULL;
		} else if (offset < resp.size) {
			available = resp.size - offset;
			copy_size = length ? min_t(size_t, length, available) : available;

			*out_buf = malloc(copy_size);
			if (!*out_buf) {
				ret = -ENOMEM;
				goto out;
			}
			memcpy(*out_buf, resp.data + offset, copy_size);
			*out_size = copy_size;
		}
	} else {
		erofs_err("HTTP range request failed with code %ld", http_code);
		ret = -EIO;
	}

out:
	if (req.headers)
		curl_slist_free_all(req.headers);
	free(req.url);
	free(resp.data);
	return ret;
}

static ssize_t ocierofs_io_pread(struct erofs_vfile *vf, void *buf, size_t len, u64 offset)
{
	struct ocierofs_iostream *oci_iostream = *(struct ocierofs_iostream **)vf->payload;
	void *download_buf = NULL;
	size_t download_size = 0;
	ssize_t ret;

	ret = ocierofs_download_blob_range(oci_iostream->ctx, offset, len,
					   &download_buf, &download_size);
	if (ret < 0)
		return ret;

	if (download_buf && download_size > 0) {
		memcpy(buf, download_buf, download_size);
		free(download_buf);
		return download_size;
	}

	return 0;
}

static ssize_t ocierofs_io_read(struct erofs_vfile *vf, void *buf, size_t len)
{
	struct ocierofs_iostream *oci_iostream = *(struct ocierofs_iostream **)vf->payload;
	ssize_t ret;

	ret = ocierofs_io_pread(vf, buf, len, oci_iostream->offset);
	if (ret > 0)
		oci_iostream->offset += ret;

	return ret;
}

static ssize_t ocierofs_io_sendfile(struct erofs_vfile *vout, struct erofs_vfile *vin,
				    off_t *pos, size_t count)
{
	struct ocierofs_iostream *oci_iostream = *(struct ocierofs_iostream **)vin->payload;
	static char buf[OCIEROFS_IO_CHUNK_SIZE];
	ssize_t total_written = 0;
	ssize_t ret = 0;

	while (count > 0) {
		size_t to_read = min_t(size_t, count, OCIEROFS_IO_CHUNK_SIZE);
		u64 read_offset = pos ? *pos : oci_iostream->offset;

		ret = ocierofs_io_pread(vin, buf, to_read, read_offset);
		if (ret <= 0) {
			if (ret < 0 && total_written == 0)
				return ret;
			break;
		}
		ssize_t written = __erofs_io_write(vout->fd, buf, ret);

		if (written < 0) {
			erofs_err("OCI I/O sendfile: failed to write to output: %s",
				  strerror(errno));
			ret = -errno;
			break;
		}

		if (written != ret) {
			erofs_err("OCI I/O sendfile: partial write: %zd != %zd", written, ret);
			ret = written;
		}

		total_written += ret;
		count -= ret;
		if (pos)
			*pos += ret;
		else
			oci_iostream->offset += ret;
	}
	return count;
}

static void ocierofs_io_close(struct erofs_vfile *vfile)
{
	struct ocierofs_iostream *oci_iostream = *(struct ocierofs_iostream **)vfile->payload;

	ocierofs_ctx_cleanup(oci_iostream->ctx);
	free(oci_iostream->ctx);
	free(oci_iostream);
	*(struct ocierofs_iostream **)vfile->payload = NULL;
}

static int ocierofs_is_erofs_native_image(struct ocierofs_ctx *ctx)
{
	if (ctx->layer_count > 0 && ctx->layers[0] &&
	    ctx->layers[0]->media_type) {
		const char *media_type = ctx->layers[0]->media_type;
		size_t len = strlen(media_type);

		if (len >= 6 && strcmp(media_type + len - 6, ".erofs") == 0)
			return 0;
	}
	return -ENOENT;
}

static struct erofs_vfops ocierofs_io_vfops = {
	.pread = ocierofs_io_pread,
	.read = ocierofs_io_read,
	.sendfile = ocierofs_io_sendfile,
	.close = ocierofs_io_close,
};

int ocierofs_io_open(struct erofs_vfile *vfile, const struct ocierofs_config *cfg)
{
	struct ocierofs_ctx *ctx;
	struct ocierofs_iostream *oci_iostream = NULL;
	int err;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	err = ocierofs_init(ctx, cfg);
	if (err) {
		free(ctx);
		return err;
	}

	err = ocierofs_is_erofs_native_image(ctx);
	if (err) {
		ocierofs_ctx_cleanup(ctx);
		free(ctx);
		return err;
	}

	oci_iostream = calloc(1, sizeof(*oci_iostream));
	if (!oci_iostream) {
		ocierofs_ctx_cleanup(ctx);
		free(ctx);
		return -ENOMEM;
	}

	oci_iostream->ctx = ctx;
	oci_iostream->offset = 0;
	*vfile = (struct erofs_vfile){.ops = &ocierofs_io_vfops};
	*(struct ocierofs_iostream **)vfile->payload = oci_iostream;
	return 0;
}
#else
int ocierofs_io_open(struct erofs_vfile *vfile, const struct ocierofs_config *cfg)
{
	return -EOPNOTSUPP;
}
#endif
