// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2025 Tencent, Inc.
 *             http://www.tencent.com/
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include "erofs/importer.h"
#include "erofs/internal.h"
#include "erofs/print.h"
#include "erofs/tar.h"
#include "liberofs_oci.h"
#include "liberofs_private.h"

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

struct erofs_oci_request {
	char *url;
	struct curl_slist *headers;
};

struct erofs_oci_response {
	char *data;
	size_t size;
	long http_code;
};

struct erofs_oci_stream {
	struct erofs_tarfile tarfile;
	const char *digest;
	int blobfd;
};

static size_t ocierofs_write_callback(void *contents, size_t size,
				      size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct erofs_oci_response *resp = userp;
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
	struct erofs_oci_stream *stream = userp;
	size_t realsize = size * nmemb;

	if (stream->blobfd < 0)
		return 0;

	if (write(stream->blobfd, contents, realsize) != realsize) {
		erofs_err("failed to write layer data for layer %s",
			  stream->digest);
		return 0;
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

static int ocierofs_curl_clear_auth(struct CURL *curl)
{
	curl_easy_setopt(curl, CURLOPT_USERPWD, NULL);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_NONE);
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

static int ocierofs_request_perform(struct erofs_oci *oci,
				    struct erofs_oci_request *req,
				    struct erofs_oci_response *resp)
{
	int ret;

	ret = ocierofs_curl_setup_rq(oci->curl, req->url,
				     OCIEROFS_HTTP_GET, req->headers,
			             ocierofs_write_callback, resp,
				     NULL, NULL);
	if (ret)
		return ret;

	ret = ocierofs_curl_perform(oci->curl, &resp->http_code);
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
 * @oci: OCI client structure
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
static char *ocierofs_get_auth_token_with_url(struct erofs_oci *oci,
					      const char *auth_url,
					      const char *service,
					      const char *repository,
					      const char *username,
					      const char *password)
{
	struct erofs_oci_request req = {};
	struct erofs_oci_response resp = {};
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
		ret = ocierofs_curl_setup_basic_auth(oci->curl, username,
						     password);
		if (ret)
			goto out_url;
	}

	ret = ocierofs_request_perform(oci, &req, &resp);
	ocierofs_curl_clear_auth(oci->curl);
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
		goto out_url;
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
	free(req.url);
	free(resp.data);
	return ret ? ERR_PTR(ret) : auth_header;
}

static char *ocierofs_discover_auth_endpoint(struct erofs_oci *oci,
					     const char *registry,
					     const char *repository)
{
	struct erofs_oci_response resp = {};
	char *realm = NULL;
	char *service = NULL;
	char *result = NULL;
	char *test_url;
	const char *api_registry;
	CURLcode res;
	long http_code;

	api_registry = (!strcmp(registry, DOCKER_REGISTRY)) ? DOCKER_API_REGISTRY : registry;

	if (asprintf(&test_url, "https://%s/v2/%s/manifests/nonexistent",
	     api_registry, repository) < 0)
		return NULL;

	curl_easy_reset(oci->curl);
	ocierofs_curl_setup_common_options(oci->curl);

	ocierofs_curl_setup_rq(oci->curl, test_url, OCIEROFS_HTTP_HEAD, NULL,
			       NULL, NULL, ocierofs_write_callback, &resp);

	res = curl_easy_perform(oci->curl);
	curl_easy_getinfo(oci->curl, CURLINFO_RESPONSE_CODE, &http_code);

	if (res == CURLE_OK && (http_code == 401 || http_code == 403 ||
	    http_code == 404) && resp.data) {
		if (ocierofs_extract_www_auth_info(resp.data, &realm, &service, NULL) == 0) {
			result = realm;
			realm = NULL;
		}
	}
	free(realm);
	free(service);
	free(resp.data);
	free(test_url);
	return result;
}

static char *ocierofs_get_auth_token(struct erofs_oci *oci, const char *registry,
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
		auth_header = ocierofs_get_auth_token_with_url(oci,
				"https://auth.docker.io/token", service, repository,
				username, password);
		if (!IS_ERR(auth_header))
			return auth_header;
	}

	discovered_auth_url = ocierofs_discover_auth_endpoint(oci, registry, repository);
	if (discovered_auth_url) {
		const char *api_registry, *auth_service;
		struct erofs_oci_response resp = {};
		char *test_url;
		CURLcode res;
		long http_code;

		api_registry = (!strcmp(registry, DOCKER_REGISTRY)) ? DOCKER_API_REGISTRY : registry;

		if (asprintf(&test_url, "https://%s/v2/%s/manifests/nonexistent",
		     api_registry, repository) >= 0) {
			curl_easy_reset(oci->curl);
			ocierofs_curl_setup_common_options(oci->curl);

			ocierofs_curl_setup_rq(oci->curl, test_url,
					       OCIEROFS_HTTP_HEAD, NULL,
					       NULL, NULL,
					       ocierofs_write_callback, &resp);

			res = curl_easy_perform(oci->curl);
			curl_easy_getinfo(oci->curl, CURLINFO_RESPONSE_CODE, &http_code);

			if (res == CURLE_OK && (http_code == 401 || http_code == 403 ||
			    http_code == 404) && resp.data) {
				char *realm = NULL;

				ocierofs_extract_www_auth_info(resp.data, &realm, &discovered_service, NULL);
				free(realm);
			}
			free(resp.data);
			free(test_url);
		}

		auth_service = discovered_service ? discovered_service : service;
		auth_header = ocierofs_get_auth_token_with_url(oci, discovered_auth_url,
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

		auth_header = ocierofs_get_auth_token_with_url(oci, auth_url,
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

static char *ocierofs_get_manifest_digest(struct erofs_oci *oci,
					  const char *registry,
					  const char *repository, const char *tag,
					  const char *platform,
					  const char *auth_header)
{
	struct erofs_oci_request req = {};
	struct erofs_oci_response resp = {};
	json_object *root, *manifests, *manifest, *platform_obj, *arch_obj;
	json_object *os_obj, *digest_obj, *schema_obj, *media_type_obj;
	char *digest = NULL;
	const char *api_registry;
	int ret = 0, len, i;

	if (!registry || !repository || !tag || !platform)
		return ERR_PTR(-EINVAL);

	api_registry = (!strcmp(registry, DOCKER_REGISTRY)) ? DOCKER_API_REGISTRY : registry;
	if (asprintf(&req.url, "https://%s/v2/%s/manifests/%s",
	     api_registry, repository, tag) < 0)
		return ERR_PTR(-ENOMEM);

	if (auth_header && strstr(auth_header, "Bearer"))
		req.headers = curl_slist_append(req.headers, auth_header);

	req.headers = curl_slist_append(req.headers,
		"Accept: " DOCKER_MEDIATYPE_MANIFEST_LIST ","
		OCI_MEDIATYPE_INDEX "," DOCKER_MEDIATYPE_MANIFEST_V1 ","
		DOCKER_MEDIATYPE_MANIFEST_V2);

	ret = ocierofs_request_perform(oci, &req, &resp);
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

		if (!strcmp(media_type, DOCKER_MEDIATYPE_MANIFEST_V2) ||
		    !strcmp(media_type, OCI_MEDIATYPE_MANIFEST)) {
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
	free(resp.data);
	if (req.headers)
		curl_slist_free_all(req.headers);
	free(req.url);

	return ret ? ERR_PTR(ret) : digest;
}

static char **ocierofs_get_layers_info(struct erofs_oci *oci,
				       const char *registry,
				       const char *repository,
				       const char *digest,
				       const char *auth_header,
				       int *layer_count)
{
	struct erofs_oci_request req = {};
	struct erofs_oci_response resp = {};
	json_object *root, *layers, *layer, *digest_obj;
	char **layers_info = NULL;
	const char *api_registry;
	int ret, len, i, j;

	if (!registry || !repository || !digest || !layer_count)
		return ERR_PTR(-EINVAL);

	*layer_count = 0;
	api_registry = (!strcmp(registry, DOCKER_REGISTRY) ?
			DOCKER_API_REGISTRY : registry);

	if (asprintf(&req.url, "https://%s/v2/%s/manifests/%s",
		     api_registry, repository, digest) < 0)
		return ERR_PTR(-ENOMEM);

	if (auth_header && strstr(auth_header, "Bearer"))
		req.headers = curl_slist_append(req.headers, auth_header);

	req.headers = curl_slist_append(req.headers,
			"Accept: " OCI_MEDIATYPE_MANIFEST "," DOCKER_MEDIATYPE_MANIFEST_V2);

	ret = ocierofs_request_perform(oci, &req, &resp);
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
		erofs_err("empty layer list in manifest");
		ret = -EINVAL;
		goto out_json;
	}

	layers_info = calloc(len, sizeof(char *));
	if (!layers_info) {
		ret = -ENOMEM;
		goto out_json;
	}

	for (i = 0; i < len; i++) {
		layer = json_object_array_get_idx(layers, i);

		if (!json_object_object_get_ex(layer, "digest", &digest_obj)) {
			erofs_err("failed to parse layer %d", i);
			ret = -EINVAL;
			goto out_free;
		}

		layers_info[i] = strdup(json_object_get_string(digest_obj));
		if (!layers_info[i]) {
			ret = -ENOMEM;
			goto out_free;
		}
	}

	*layer_count = len;
	json_object_put(root);
	free(resp.data);
	if (req.headers)
		curl_slist_free_all(req.headers);
	free(req.url);
	return layers_info;

out_free:
	if (layers_info) {
		for (j = 0; j < i; j++)
			free(layers_info[j]);
	}
	free(layers_info);
out_json:
	json_object_put(root);
out:
	free(resp.data);
	if (req.headers)
		curl_slist_free_all(req.headers);
	free(req.url);
	return ERR_PTR(ret);
}

static int ocierofs_extract_layer(struct erofs_oci *oci, struct erofs_importer *importer,
				  const char *digest, const char *auth_header)
{
	struct erofs_oci_request req = {};
	struct erofs_oci_stream stream = {};
	const char *api_registry;
	long http_code;
	int ret;

	stream = (struct erofs_oci_stream) {
		.digest = digest,
		.blobfd = erofs_tmpfile(),
	};
	if (stream.blobfd < 0) {
		erofs_err("failed to create temporary file for %s", digest);
		return -errno;
	}

	api_registry = (!strcmp(oci->params.registry, DOCKER_REGISTRY)) ?
		       DOCKER_API_REGISTRY : oci->params.registry;
	if (asprintf(&req.url, "https://%s/v2/%s/blobs/%s",
	     api_registry, oci->params.repository, digest) == -1) {
		ret = -ENOMEM;
		goto out;
	}

	if (auth_header && strstr(auth_header, "Bearer"))
		req.headers = curl_slist_append(req.headers, auth_header);

	curl_easy_reset(oci->curl);

	ret = ocierofs_curl_setup_common_options(oci->curl);
	if (ret)
		goto out;

	ret = ocierofs_curl_setup_rq(oci->curl, req.url, OCIEROFS_HTTP_GET,
				     req.headers,
				     ocierofs_layer_write_callback,
				     &stream, NULL, NULL);
	if (ret)
		goto out;

	ret = ocierofs_curl_perform(oci->curl, &http_code);
	if (ret)
		goto out;

	if (http_code < 200 || http_code >= 300) {
		erofs_err("HTTP request failed with code %ld", http_code);
		ret = -EIO;
		goto out;
	}

	if (lseek(stream.blobfd, 0, SEEK_SET) < 0) {
		erofs_err("failed to seek to beginning of temp file: %s",
			  strerror(errno));
		ret = -errno;
		goto out;
	}

	memset(&stream.tarfile, 0, sizeof(stream.tarfile));
	init_list_head(&stream.tarfile.global.xattrs);

	ret = erofs_iostream_open(&stream.tarfile.ios, stream.blobfd,
				  EROFS_IOS_DECODER_GZIP);
	if (ret) {
		erofs_err("failed to initialize tar stream: %s",
			  erofs_strerror(ret));
		goto out;
	}

	do {
		ret = tarerofs_parse_tar(importer, &stream.tarfile);
		/* Continue parsing until end of archive */
	} while (!ret);
	erofs_iostream_close(&stream.tarfile.ios);

	if (ret < 0 && ret != -ENODATA) {
		erofs_err("failed to process tar stream: %s",
			  erofs_strerror(ret));
		goto out;
	}
	ret = 0;

out:
	if (stream.blobfd >= 0)
		close(stream.blobfd);
	if (req.headers)
		curl_slist_free_all(req.headers);
	free(req.url);
	return ret;
}

/**
 * ocierofs_build_trees - Build file trees from OCI container image layers
 * @importer: EROFS importer structure
 * @oci: OCI client structure with configured parameters
 *
 * Extract and build file system trees from all layers of an OCI container
 * image.
 *
 * Return: 0 on success, negative errno on failure
 */
int ocierofs_build_trees(struct erofs_importer *importer, struct erofs_oci *oci)
{
	char *auth_header = NULL;
	char *manifest_digest = NULL;
	char **layers = NULL;
	int layer_count = 0;
	int ret, i;

	if (!importer || !oci)
		return -EINVAL;

	if (oci->params.username && oci->params.password &&
	    oci->params.username[0] && oci->params.password[0]) {
		auth_header = ocierofs_get_auth_token(oci,
						      oci->params.registry,
						      oci->params.repository,
						      oci->params.username,
						      oci->params.password);
		if (IS_ERR(auth_header)) {
			auth_header = NULL;
			ret = ocierofs_curl_setup_basic_auth(oci->curl,
							     oci->params.username,
							     oci->params.password);
			if (ret)
				goto out;
		}
	} else {
		auth_header = ocierofs_get_auth_token(oci,
						      oci->params.registry,
						      oci->params.repository,
						      NULL, NULL);
		if (IS_ERR(auth_header))
			auth_header = NULL;
	}

	manifest_digest = ocierofs_get_manifest_digest(oci, oci->params.registry,
						       oci->params.repository,
						       oci->params.tag,
						       oci->params.platform,
						       auth_header);
	if (IS_ERR(manifest_digest)) {
		ret = PTR_ERR(manifest_digest);
		erofs_err("failed to get manifest digest: %s",
			  erofs_strerror(ret));
		goto out_auth;
	}

	layers = ocierofs_get_layers_info(oci, oci->params.registry,
					  oci->params.repository,
					  manifest_digest, auth_header,
					  &layer_count);
	if (IS_ERR(layers)) {
		ret = PTR_ERR(layers);
		erofs_err("failed to get image layers: %s", erofs_strerror(ret));
		goto out_manifest;
	}

	if (oci->params.layer_index >= 0) {
		if (oci->params.layer_index >= layer_count) {
			erofs_err("layer index %d exceeds available layers (%d)",
				  oci->params.layer_index, layer_count);
			ret = -EINVAL;
			goto out_layers;
		}
		layer_count = 1;
		i = oci->params.layer_index;
	} else {
		i = 0;
	}

	while (i < layer_count) {
		char *trimmed = erofs_trim_for_progressinfo(layers[i],
				sizeof("Extracting layer  ...") - 1);
		erofs_update_progressinfo("Extracting layer %d: %s ...", i,
					  trimmed);
		free(trimmed);
		ret = ocierofs_extract_layer(oci, importer, layers[i],
					     auth_header);
		if (ret) {
			erofs_err("failed to extract layer %d: %s", i,
				  erofs_strerror(ret));
			break;
		}
		i++;
	}
out_layers:
	for (i = 0; i < layer_count; i++)
		free(layers[i]);
	free(layers);
out_manifest:
	free(manifest_digest);
out_auth:
	free(auth_header);

	if (oci->params.username && oci->params.password &&
	    oci->params.username[0] && oci->params.password[0] &&
	    !auth_header) {
		ocierofs_curl_clear_auth(oci->curl);
	}
out:
	return ret;
}

/**
 * ocierofs_init - Initialize OCI client with default parameters
 * @oci: OCI client structure to initialize
 *
 * Initialize OCI client structure, set up CURL handle, and configure
 * default parameters including platform (linux/amd64), registry
 * (registry-1.docker.io), and tag (latest).
 *
 * Return: 0 on success, negative errno on failure
 */
int ocierofs_init(struct erofs_oci *oci)
{
	if (!oci)
		return -EINVAL;

	*oci = (struct erofs_oci){};
	oci->curl = curl_easy_init();
	if (!oci->curl)
		return -EIO;

	if (ocierofs_curl_setup_common_options(oci->curl)) {
		ocierofs_cleanup(oci);
		return -EIO;
	}

	if (erofs_oci_params_set_string(&oci->params.platform,
				"linux/amd64") ||
	    erofs_oci_params_set_string(&oci->params.registry,
				DOCKER_API_REGISTRY) ||
	    erofs_oci_params_set_string(&oci->params.tag, "latest")) {
		ocierofs_cleanup(oci);
		return -ENOMEM;
	}
	oci->params.layer_index = -1; /* -1 means extract all layers */
	return 0;
}

/**
 * ocierofs_cleanup - Clean up OCI client and free allocated resources
 * @oci: OCI client structure to clean up
 *
 * Clean up CURL handle, free all allocated string parameters, and
 * reset the OCI client structure to a clean state.
 */
void ocierofs_cleanup(struct erofs_oci *oci)
{
	if (!oci)
		return;

	if (oci->curl) {
		curl_easy_cleanup(oci->curl);
		oci->curl = NULL;
	}

	free(oci->params.registry);
	free(oci->params.repository);
	free(oci->params.tag);
	free(oci->params.platform);
	free(oci->params.username);
	free(oci->params.password);

	oci->params.registry = NULL;
	oci->params.repository = NULL;
	oci->params.tag = NULL;
	oci->params.platform = NULL;
	oci->params.username = NULL;
	oci->params.password = NULL;
}

int erofs_oci_params_set_string(char **field, const char *value)
{
	char *new_value;

	if (!field)
		return -EINVAL;

	if (!value) {
		free(*field);
		*field = NULL;
		return 0;
	}

	new_value = strdup(value);
	if (!new_value)
		return -ENOMEM;

	free(*field);
	*field = new_value;
	return 0;
}

int ocierofs_parse_ref(struct erofs_oci *oci, const char *ref_str)
{
	char *slash, *colon, *dot;
	const char *repo_part;
	size_t len;

	slash = strchr(ref_str, '/');
	if (slash) {
		dot = strchr(ref_str, '.');
		if (dot && dot < slash) {
			char *registry_str;

			len = slash - ref_str;
			registry_str = strndup(ref_str, len);

			if (!registry_str) {
				erofs_err("failed to allocate memory for registry");
				return -ENOMEM;
			}
			if (erofs_oci_params_set_string(&oci->params.registry,
							registry_str)) {
				free(registry_str);
				erofs_err("failed to set registry");
				return -ENOMEM;
			}
			free(registry_str);
			repo_part = slash + 1;
		} else {
			repo_part = ref_str;
		}
	} else {
		repo_part = ref_str;
	}

	colon = strchr(repo_part, ':');
	if (colon) {
		char *repo_str;

		len = colon - repo_part;
		repo_str = strndup(repo_part, len);

		if (!repo_str) {
			erofs_err("failed to allocate memory for repository");
			return -ENOMEM;
		}

		if (!strchr(repo_str, '/') &&
		    (!strcmp(oci->params.registry, DOCKER_API_REGISTRY) ||
		     !strcmp(oci->params.registry, DOCKER_REGISTRY))) {
			char *full_repo;

			if (asprintf(&full_repo, "library/%s", repo_str) == -1) {
				free(repo_str);
				erofs_err("failed to allocate memory for full repository name");
				return -ENOMEM;
			}
			free(repo_str);
			repo_str = full_repo;
		}

		if (erofs_oci_params_set_string(&oci->params.repository,
						repo_str)) {
			free(repo_str);
			erofs_err("failed to set repository");
			return -ENOMEM;
		}
		free(repo_str);

		if (erofs_oci_params_set_string(&oci->params.tag,
						colon + 1)) {
			erofs_err("failed to set tag");
			return -ENOMEM;
		}
	} else {
		char *repo_str = strdup(repo_part);

		if (!repo_str) {
			erofs_err("failed to allocate memory for repository");
			return -ENOMEM;
		}

		if (!strchr(repo_str, '/') &&
		    (!strcmp(oci->params.registry, DOCKER_API_REGISTRY) ||
		     !strcmp(oci->params.registry, DOCKER_REGISTRY))) {
			char *full_repo;

			if (asprintf(&full_repo, "library/%s", repo_str) == -1) {
				free(repo_str);
				erofs_err("failed to allocate memory for full repository name");
				return -ENOMEM;
			}
			free(repo_str);
			repo_str = full_repo;
		}

		if (erofs_oci_params_set_string(&oci->params.repository,
						repo_str)) {
			free(repo_str);
			erofs_err("failed to set repository");
			return -ENOMEM;
		}
		free(repo_str);
	}

	return 0;
}
