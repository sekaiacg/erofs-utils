// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2025 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Yifan Zhao <zhaoyifan28@huawei.com>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <curl/curl.h>
#include <libxml/parser.h>
#include <openssl/hmac.h>
#include "erofs/internal.h"
#include "erofs/print.h"
#include "erofs/inode.h"
#include "erofs/blobchunk.h"
#include "erofs/diskbuf.h"
#include "erofs/importer.h"
#include "liberofs_rebuild.h"
#include "liberofs_s3.h"

#define S3EROFS_PATH_MAX		1024
#define S3EROFS_MAX_QUERY_PARAMS	16
#define S3EROFS_URL_LEN			8192
#define S3EROFS_CANONICAL_URI_LEN	2048
#define S3EROFS_CANONICAL_QUERY_LEN	S3EROFS_URL_LEN

#define BASE64_ENCODE_LEN(len)	(((len + 2) / 3) * 4)

struct s3erofs_query_params {
	int num;
	const char *key[S3EROFS_MAX_QUERY_PARAMS];
	const char *value[S3EROFS_MAX_QUERY_PARAMS];
};

struct s3erofs_curl_request {
	char url[S3EROFS_URL_LEN];
	char canonical_uri[S3EROFS_CANONICAL_URI_LEN];
	char canonical_query[S3EROFS_CANONICAL_QUERY_LEN];
};

static const char *s3erofs_parse_host(const char *endpoint, const char **schema)
{
	const char *host, *split;

	split = strstr(endpoint, "://");
	if (!split) {
		host = endpoint;
		if (schema)
			*schema = NULL;
	} else {
		host = split + sizeof("://") - 1;
		if (schema) {
			*schema = strndup(endpoint, host - endpoint);
			if (!*schema)
				return ERR_PTR(-ENOMEM);
		}
	}
	return host;
}

static void *s3erofs_urlencode(const char *input)
{
	static const char hex[] = "0123456789ABCDEF";
	char *p, *url;
	int i, c;

	url = malloc(strlen(input) * 3 + 1);
	if (!url)
		return ERR_PTR(-ENOMEM);

	p = url;
	for (i = 0; i < strlen(input); ++i) {
		c = input[i];

		// Unreserved characters: A-Z a-z 0-9 - . _ ~
		if (isalpha(c) || isdigit(c) || c == '-' || c == '.' ||
		    c == '_' || c == '~') {
			*p++ = c;
		} else {
			*p++ = '%';
			*p++ = hex[c >> 4];
			*p++ = hex[c & 0x0F];
		}
	}
	*p = '\0';
	return url;
}

struct s3erofs_qsort_kv {
	char *key;
	char *value;
};

static int compare_kv_pair(const void *a, const void *b)
{
	return strcmp(((const struct s3erofs_qsort_kv *)a)->key,
		      ((const struct s3erofs_qsort_kv *)b)->key);
}

static int s3erofs_prepare_canonical_query(struct s3erofs_curl_request *req,
					   struct s3erofs_query_params *params)
{
	struct s3erofs_qsort_kv *pairs;
	int i, pos = 0, ret = 0;

	if (!params->num)
		return 0;

	pairs = calloc(1, sizeof(struct s3erofs_qsort_kv) * params->num);
	for (i = 0; i < params->num; i++) {
		pairs[i].key = s3erofs_urlencode(params->key[i]);
		if (IS_ERR(pairs[i].key)) {
			ret = PTR_ERR(pairs[i].key);
			pairs[i].key = NULL;
			goto out;
		}
		pairs[i].value = s3erofs_urlencode(params->value[i]);
		if (IS_ERR(pairs[i].value)) {
			ret = PTR_ERR(pairs[i].value);
			pairs[i].value = NULL;
			goto out;
		}
	}

	qsort(pairs, params->num, sizeof(struct s3erofs_qsort_kv), compare_kv_pair);
	for (i = 0; i < params->num; i++)
		pos += snprintf(req->canonical_query + pos,
				S3EROFS_CANONICAL_QUERY_LEN - pos, "%s=%s%s",
				pairs[i].key, pairs[i].value,
				(i == params->num - 1) ? "" : "&");
	req->canonical_query[pos] = '\0';
out:
	for (i = 0; i < params->num; i++) {
		free(pairs[i].key);
		free(pairs[i].value);
	}
	free(pairs);
	return ret;
}

static int s3erofs_prepare_url(struct s3erofs_curl_request *req,
			       const char *endpoint,
			       const char *path, const char *key,
			       struct s3erofs_query_params *params,
			       enum s3erofs_url_style url_style,
			       enum s3erofs_signature_version sig)
{
	static const char https[] = "https://";
	const char *schema, *host;
	/* an additional slash is added, which wasn't specified by user inputs */
	bool slash = false;
	char *url = req->url;
	int pos, canonical_uri_pos, i, ret = 0;

	if (!endpoint || !path)
		return -EINVAL;

	host = s3erofs_parse_host(endpoint, &schema);
	if (IS_ERR(host))
		return PTR_ERR(host);
	if (!schema)
		schema = https;

	if (url_style == S3EROFS_URL_STYLE_PATH) {
		pos = snprintf(url, S3EROFS_URL_LEN, "%s%s/%s", schema,
			       host, path);
		canonical_uri_pos = pos - strlen(path) - 1;
	} else {
		const char * split = strchr(path, '/');

		if (!split) {
			pos = snprintf(url, S3EROFS_URL_LEN, "%s%s.%s/",
				       schema, path, host);
			canonical_uri_pos = pos - 1;
			slash = true;
		} else {
			pos = snprintf(url, S3EROFS_URL_LEN, "%s%.*s.%s%s",
				       schema, (int)(split - path), path,
				       host, split);
			canonical_uri_pos = pos - strlen(split);
		}
	}
	if (key) {
		if (url[pos - 1] == '/')
			--pos;
		else
			slash = true;
		pos += snprintf(url + pos, S3EROFS_URL_LEN - pos, "/%s", key);
	}

	if (sig == S3EROFS_SIGNATURE_VERSION_2)
		i = snprintf(req->canonical_uri, S3EROFS_CANONICAL_URI_LEN,
			     "/%s%s%s", path, slash ? "/" : "", key ? key : "");
	else
		i = snprintf(req->canonical_uri, S3EROFS_CANONICAL_URI_LEN,
			     "%s", url + canonical_uri_pos);
	req->canonical_uri[i] = '\0';

	if (params) {
		for (i = 0; i < params->num; i++)
			pos += snprintf(url + pos, S3EROFS_URL_LEN - pos, "%c%s=%s",
					(!i ? '?' : '&'), params->key[i],
					params->value[i]);
		ret = s3erofs_prepare_canonical_query(req, params);
		if (ret < 0)
			goto err;
	}

	erofs_dbg("Request URL %s", url);
	erofs_dbg("Request canonical_uri %s", req->canonical_uri);

err:
	if (schema != https)
		free((void *)schema);
	return ret;
}

static char *get_canonical_headers(const struct curl_slist *list)
{
	const struct curl_slist *current = list;
	char *result;
	size_t len = 0;

	while (current) {
		len += strlen(current->data) + 1;
		current = current->next;
	}

	result = (char *)malloc(len + 1);
	if (!result)
		return NULL;

	current = list;
	len = 0;
	while (current) {
		strcpy(result + len, current->data);
		len += strlen(current->data);
		result[len++] = '\n';
		current = current->next;
	}

	result[len] = '\0';
	return result;
}

enum s3erofs_date_format {
	S3EROFS_DATE_RFC1123,
	S3EROFS_DATE_ISO8601,
	S3EROFS_DATE_YYYYMMDD
};

static void s3erofs_now(char *buf, size_t maxlen, enum s3erofs_date_format fmt)
{
	const char *format;
	time_t now = time(NULL);
	struct tm *ptm = gmtime(&now);

	switch (fmt) {
	case S3EROFS_DATE_RFC1123:
		format = "%a, %d %b %Y %H:%M:%S GMT";
		break;
	case S3EROFS_DATE_ISO8601:
		format = "%Y%m%dT%H%M%SZ";
		break;
	case S3EROFS_DATE_YYYYMMDD:
		format = "%Y%m%d";
		break;
	default:
		erofs_err("unknown date format %d", fmt);
		buf[0] = '\0';
		return;
	}

	strftime(buf, maxlen, format, ptm);
}

static void s3erofs_to_hex(const u8 *data, size_t len, char *output)
{
	static const char hex_chars[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		output[i * 2] = hex_chars[data[i] >> 4];
		output[i * 2 + 1] = hex_chars[data[i] & 0x0f];
	}
	output[len * 2] = '\0';
}

// See: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTAuthentication.html#ConstructingTheAuthenticationHeader
static char *s3erofs_sigv2_header(const struct curl_slist *headers,
				  const char *content_md5,
				  const char *content_type, const char *date,
				  const char *canonical_uri, const char *ak,
				  const char *sk)
{
	u8 hmac_signature[EVP_MAX_MD_SIZE];
	char *str, *output = NULL;
	unsigned int len, pos, output_len;
	const char *prefix = "Authorization: AWS ";

	if (!date || !ak || !sk)
		return ERR_PTR(-EINVAL);

	if (!content_md5)
		content_md5 = "";
	if (!content_type)
		content_type = "";
	if (!canonical_uri)
		canonical_uri = "/";

	pos = asprintf(&str, "GET\n%s\n%s\n%s\n%s%s", content_md5, content_type,
		       date, "", canonical_uri);
	if (pos < 0)
		return ERR_PTR(-ENOMEM);

	if (!HMAC(EVP_sha1(), sk, strlen(sk), (u8 *)str, strlen(str), hmac_signature, &len))
		goto free_string;

	output_len = BASE64_ENCODE_LEN(len);
	output_len += strlen(prefix);
	output_len += strlen(ak);
	output_len += 1;	/* for ':' between ak and signature */

	output = (char *)malloc(output_len + 1);
	if (!output)
		goto free_string;

	pos = snprintf(output, output_len, "%s%s:", prefix, ak);
	if (pos < 0)
		goto free_string;
	EVP_EncodeBlock((u8 *)output + pos, hmac_signature, len);
free_string:
	free(str);
	return output ?: ERR_PTR(-ENOMEM);
}

// See: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
static char *s3erofs_sigv4_header(const struct curl_slist *headers,
				  const char *canonical_uri,
				  const char *canonical_query,
				  const char *region, const char *ak,
				  const char *sk)
{
	u8 ping_buf[EVP_MAX_MD_SIZE], pong_buf[EVP_MAX_MD_SIZE];
	char hex_buf[EVP_MAX_MD_SIZE * 2 + 1];
	char date_str[16], timestamp[32];
	char *canonical_request, *canonical_headers;
	char *string_to_sign, *scope, *aws4_secret;
	unsigned int len;
	char *output = NULL;
	int err = 0;

	if (!canonical_uri || !region || !ak || !sk)
		return ERR_PTR(-EINVAL);

	if (!canonical_query)
		canonical_query = "";

	canonical_headers = get_canonical_headers(headers);

	// Get current time in required formats
	s3erofs_now(date_str, sizeof(date_str), S3EROFS_DATE_YYYYMMDD);
	s3erofs_now(timestamp, sizeof(timestamp), S3EROFS_DATE_ISO8601);

	// Task 1: Create canonical request
	if (asprintf(&canonical_request,
		     "GET\n"
		     "%s\n"
		     "%s\n"
		     "%s\n"
		     "host;x-amz-content-sha256;x-amz-date\n"
		     "UNSIGNED-PAYLOAD",
		     canonical_uri, canonical_query, canonical_headers) < 0) {
		err = -ENOMEM;
		goto err_canonical_headers;
	}

	// Hash the canonical request
	if (!EVP_Digest(canonical_request, strlen(canonical_request), ping_buf,
			&len, EVP_sha256(), NULL)) {
		err = -EIO;
		goto err_canonical_request;
	}
	s3erofs_to_hex(ping_buf, len, hex_buf);

	// Task 2: Create string to sign
	if (asprintf(&scope, "%s/%s/s3/aws4_request", date_str, region) < 0) {
		err = -ENOMEM;
		goto err_canonical_request;
	}
	if (asprintf(&string_to_sign,
		     "AWS4-HMAC-SHA256\n"
		     "%s\n" // timestamp (ISO8601, e.g., 20251115T123456Z)
		     "%s\n" // credential scope (e.g., 20251115/us-east-1/s3/aws4_request)
		     "%s",  // canonical request hash (hex-encoded SHA-256)
		     timestamp, scope, hex_buf) < 0) {
		err = -ENOMEM;
		goto err_scope;
	}

	// Task 3: Calculate signing key
	if (asprintf(&aws4_secret, "AWS4%s", sk) < 0) {
		err = -ENOMEM;
		goto err_string_to_sign;
	}
	if (!HMAC(EVP_sha256(), aws4_secret, strlen(aws4_secret),
		  (u8 *)date_str, strlen(date_str), ping_buf, &len)) {
		err = -EIO;
		goto err_aws4_secret;
	}
	if (!HMAC(EVP_sha256(), ping_buf, len, (u8 *)region, strlen(region),
		  pong_buf, &len)) {
		err = -EIO;
		goto err_aws4_secret;
	}
	if (!HMAC(EVP_sha256(), pong_buf, len, (u8 *)"s3", strlen("s3"),
		  ping_buf, &len)) {
		err = -EIO;
		goto err_aws4_secret;
	}
	if (!HMAC(EVP_sha256(), ping_buf, len, (u8 *)"aws4_request",
		  strlen("aws4_request"), pong_buf, &len)) {
		err = -EIO;
		goto err_aws4_secret;
	}

	// Calculate signature
	if (!HMAC(EVP_sha256(), pong_buf, len, (u8 *)string_to_sign,
		  strlen(string_to_sign), ping_buf, &len)) {
		err = -EIO;
		goto err_aws4_secret;
	}
	s3erofs_to_hex(ping_buf, len, hex_buf);

	// Build Authorization header
	if (asprintf(&output,
		     "Authorization: AWS4-HMAC-SHA256 "
		     "Credential=%s/%s, "
		     "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
		     "Signature=%s",
		     ak, scope, hex_buf) < 0) {
		err = -ENOMEM;
		goto err_aws4_secret;
	}

err_aws4_secret:
	free(aws4_secret);
err_string_to_sign:
	free(string_to_sign);
err_scope:
	free(scope);
err_canonical_request:
	free(canonical_request);
err_canonical_headers:
	free(canonical_headers);
	return err ? ERR_PTR(err) : output;
}

static int s3erofs_request_insert_auth_v2(struct curl_slist **request_headers,
					  struct s3erofs_curl_request *req,
					  struct erofs_s3 *s3)
{
	static const char date_prefix[] = "Date: ";
	char date[64], *sigv2;

	memcpy(date, date_prefix, sizeof(date_prefix) - 1);
	s3erofs_now(date + sizeof(date_prefix) - 1,
		    sizeof(date) - sizeof(date_prefix) + 1,
		    S3EROFS_DATE_RFC1123);

	sigv2 = s3erofs_sigv2_header(*request_headers, NULL, NULL,
				     date + sizeof(date_prefix) - 1, req->canonical_uri,
				     s3->access_key, s3->secret_key);
	if (IS_ERR(sigv2))
		return PTR_ERR(sigv2);

	*request_headers = curl_slist_append(*request_headers, date);
	*request_headers = curl_slist_append(*request_headers, sigv2);

	free(sigv2);
	return 0;
}

static int s3erofs_request_insert_auth_v4(struct curl_slist **request_headers,
					  struct s3erofs_curl_request *req,
					  struct erofs_s3 *s3)
{
	char timestamp[32], *sigv4, *tmp;
	const char *host, *host_end;

	/* Add following headers for SigV4 in alphabetical order: */
	/* 1. host */
	host = s3erofs_parse_host(req->url, NULL);
	host_end = strchr(host, '/');
	if (!host_end)
		return -EINVAL;
	if (asprintf(&tmp, "host:%.*s", (int)(host_end - host), host) < 0)
		return -ENOMEM;
	*request_headers = curl_slist_append(*request_headers, tmp);
	free(tmp);

	/* 2. x-amz-content-sha256 */
	*request_headers = curl_slist_append(
		*request_headers, "x-amz-content-sha256:UNSIGNED-PAYLOAD");

	/* 3. x-amz-date */
	s3erofs_now(timestamp, sizeof(timestamp), S3EROFS_DATE_ISO8601);
	if (asprintf(&tmp, "x-amz-date:%s", timestamp) < 0)
		return -ENOMEM;
	*request_headers = curl_slist_append(*request_headers, tmp);
	free(tmp);

	sigv4 = s3erofs_sigv4_header(*request_headers, req->canonical_uri,
				     req->canonical_query, s3->region, s3->access_key,
				     s3->secret_key);
	if (IS_ERR(sigv4))
		return PTR_ERR(sigv4);
	*request_headers = curl_slist_append(*request_headers, sigv4);
	free(sigv4);

	return 0;
}

struct s3erofs_curl_response {
	char *data;
	size_t size;
};

static size_t s3erofs_request_write_memory_cb(void *contents, size_t size,
					      size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct s3erofs_curl_response *response = userp;
	void *tmp;

	tmp = realloc(response->data, response->size + realsize + 1);
	if (tmp == NULL)
		return 0;

	response->data = tmp;

	memcpy(response->data + response->size, contents, realsize);
	response->size += realsize;
	response->data[response->size] = '\0';
	return realsize;
}

static int s3erofs_request_perform(struct erofs_s3 *s3,
				   struct s3erofs_curl_request *req, void *resp)
{
	struct curl_slist *request_headers = NULL;
	CURL *curl = s3->easy_curl;
	long http_code = 0;
	int ret;

	if (s3->access_key[0]) {
		if (s3->sig == S3EROFS_SIGNATURE_VERSION_4)
			ret = s3erofs_request_insert_auth_v4(&request_headers, req, s3);
		else
			ret = s3erofs_request_insert_auth_v2(&request_headers, req, s3);
		if (ret < 0) {
			erofs_err("failed to insert auth headers");
			return ret;
		}
	}

	curl_easy_setopt(curl, CURLOPT_URL, req->url);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_headers);

	ret = curl_easy_perform(curl);
	if (ret != CURLE_OK) {
		erofs_err("curl_easy_perform() failed: %s",
			  curl_easy_strerror(ret));
		ret = -EIO;
		goto err_header;
	}

	ret = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (ret != CURLE_OK) {
		erofs_err("curl_easy_getinfo() failed: %s",
			  curl_easy_strerror(ret));
		ret = -EIO;
		goto err_header;
	}

	if (!(http_code >= 200 && http_code < 300)) {
		erofs_err("request failed with HTTP code %ld", http_code);
		ret = -EIO;
	}

err_header:
	curl_slist_free_all(request_headers);
	return ret;
}

struct s3erofs_object_info {
	char *key;
	u64 size;
	time_t mtime;
	u32 mtime_ns;
};

struct s3erofs_object_iterator {
	struct erofs_s3 *s3;
	struct s3erofs_object_info *objects;
	int cur;

	char *bucket, *prefix;
	const char *delimiter;

	char *next_marker;
	bool is_truncated;
};

static int s3erofs_parse_list_objects_one(xmlNodePtr node,
					  struct s3erofs_object_info *info)
{
	xmlNodePtr child;
	xmlChar *str;

	for (child = node->children; child; child = child->next) {
		if (child->type == XML_ELEMENT_NODE) {
			str = xmlNodeGetContent(child);
			if (!str)
				return -ENOMEM;

			if (xmlStrEqual(child->name, (const xmlChar *)"LastModified")) {
				struct tm tm;
				char *end;

				end = strptime((char *)str, "%Y-%m-%dT%H:%M:%S", &tm);
				if (!end || (*end != '.' && *end != 'Z' && *end != '\0')) {
					xmlFree(str);
					return -EIO;
				}
				if (*end == '.') {
					info->mtime_ns = strtoul(end + 1, &end, 10);
					if (*end != 'Z' && *end != '\0') {
						xmlFree(str);
						return -EIO;
					}
				}
				/*
				 * Not set by strptime(); tells mktime() to determine
				 * whether daylight saving time is in effect
				 */
				tm.tm_isdst = -1;
				info->mtime = mktime(&tm);
			}
			if (xmlStrEqual(child->name, (const xmlChar *)"Key"))
				info->key = strdup((char *)str);
			else if (xmlStrEqual(child->name, (const xmlChar *)"Size"))
				info->size = atoll((char *)str);
			xmlFree(str);
		}
	}
	return 0;
}

static int s3erofs_parse_list_objects_result(const char *data, int len,
					     struct s3erofs_object_iterator *it)
{
	xmlNodePtr root = NULL, node, next;
	int ret, i, contents_count;
	xmlDocPtr doc = NULL;
	xmlChar *str;
	void *tmp;

	doc = xmlReadMemory(data, len, NULL, NULL, 0);
	if (!doc) {
		erofs_err("failed to parse XML data");
		return -EINVAL;
	}

	root = xmlDocGetRootElement(doc);
	if (!root) {
		erofs_err("failed to get root element");
		ret = -EINVAL;
		goto out;
	}

	if (!xmlStrEqual(root->name, (const xmlChar *)"ListBucketResult")) {
		erofs_err("invalid root element: expected ListBucketResult, got %s", root->name);
		ret = -EINVAL;
		goto out;
	}

	// https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html#AmazonS3-ListObjects-response-NextMarker
	free(it->next_marker);
	it->next_marker = NULL;

	contents_count = 1;
	for (node = root->children; node; node = next) {
		next = node->next;
		if (node->type == XML_ELEMENT_NODE) {
			if (xmlStrEqual(node->name, (const xmlChar *)"Contents")) {
				++contents_count;
				continue;
			}
			if (xmlStrEqual(node->name, (const xmlChar *)"IsTruncated")) {
				str = xmlNodeGetContent(node);
				if (str) {
					it->is_truncated =
						!!xmlStrEqual(str, (const xmlChar *)"true");
					xmlFree(str);
				}
			} else if (xmlStrEqual(node->name, (const xmlChar *)"NextMarker")) {
				str = xmlNodeGetContent(node);
				if (str) {
					it->next_marker = strdup((char *)str);
					xmlFree(str);
					if (!it->next_marker) {
						ret = -ENOMEM;
						goto out;
					}
				}
			}
			xmlUnlinkNode(node);
		}
		xmlUnlinkNode(node);
		xmlFreeNode(node);
	}

	i = 0;
	if (it->objects) {
		for (; it->objects[i].key; ++i) {
			free(it->objects[i].key);
			it->objects[i].key = NULL;
		}
	}

	if (i + 1 < contents_count) {
		tmp = malloc(contents_count * sizeof(*it->objects));
		if (!tmp) {
			ret = -ENOMEM;
			goto out;
		}
		free(it->objects);
		it->objects = tmp;
		it->objects[0].key = NULL;
	}
	it->cur = 0;

	ret = 0;
	for (i = 0, node = root->children; node; node = node->next) {
		if (__erofs_unlikely(i >= contents_count - 1)) {
			DBG_BUGON(1);
			continue;
		}
		ret = s3erofs_parse_list_objects_one(node, &it->objects[i]);
		if (ret < 0) {
			erofs_err("failed to parse contents node %s: %s",
				  (const char *)node->name, erofs_strerror(ret));
			break;
		}
		it->objects[++i].key = NULL;
	}

	/*
	 * `NextMarker` is returned only if the `delimiter` request parameter
	 * is specified.
	 *
	 * If the response is truncated and does not include `NextMarker`, use
	 * the value of the last `Key` element in the response as the `marker`
	 * parameter in the next request.
	 */
	if (!ret && i && it->is_truncated && !it->next_marker) {
		it->next_marker = strdup(it->objects[i - 1].key);
		if (!it->next_marker)
			ret = -ENOMEM;
	}

	if (!ret)
		ret = i;
out:
	xmlFreeDoc(doc);
	return ret;
}

static int s3erofs_list_objects(struct s3erofs_object_iterator *it)
{
	struct s3erofs_curl_request req = {};
	struct s3erofs_curl_response resp = {};
	struct s3erofs_query_params params;
	struct erofs_s3 *s3 = it->s3;
	int ret = 0;

	if (it->delimiter && strlen(it->delimiter) > S3EROFS_PATH_MAX) {
		erofs_err("delimiter is too long");
		return -EINVAL;
	}

	params.num = 0;
	if (it->prefix) {
		params.key[params.num] = "prefix";
		params.value[params.num] = it->prefix;
		++params.num;
	}

	if (it->delimiter) {
		params.key[params.num] = "delimiter";
		params.value[params.num] = it->delimiter;
		++params.num;
	}

	if (it->next_marker) {
		params.key[params.num] = "marker";
		params.value[params.num] = it->next_marker;
		++params.num;
	}

	ret = s3erofs_prepare_url(&req, s3->endpoint, it->bucket, NULL, &params,
				  s3->url_style, s3->sig);
	if (ret < 0)
		return ret;

	if (curl_easy_setopt(s3->easy_curl, CURLOPT_WRITEFUNCTION,
			     s3erofs_request_write_memory_cb) != CURLE_OK)
		return -EIO;

	ret = s3erofs_request_perform(s3, &req, &resp);
	if (ret >= 0)
		ret = s3erofs_parse_list_objects_result(resp.data, resp.size, it);
	free(resp.data);
	return ret;
}

static struct s3erofs_object_iterator *
s3erofs_create_object_iterator(struct erofs_s3 *s3, const char *path,
			       const char *delimiter)
{
	struct s3erofs_object_iterator *iter;
	char *prefix;

	iter = calloc(1, sizeof(struct s3erofs_object_iterator));
	if (!iter)
		return ERR_PTR(-ENOMEM);
	iter->s3 = s3;
	prefix = strchr(path, '/');
	if (prefix) {
		if (++prefix - path > S3EROFS_PATH_MAX)
			return ERR_PTR(-EINVAL);
		iter->bucket = strndup(path, prefix - path);
		iter->prefix = strdup(prefix);
	} else {
		iter->bucket = strdup(path);
		iter->prefix = NULL;
	}
	iter->delimiter = delimiter;
	iter->is_truncated = true;
	return iter;
}

static void s3erofs_destroy_object_iterator(struct s3erofs_object_iterator *it)
{
	int i;

	if (it->next_marker)
		free(it->next_marker);
	if (it->objects) {
		for (i = 0; it->objects[i].key; ++i)
			free(it->objects[i].key);
		free(it->objects);
	}
	free(it->prefix);
	free(it->bucket);
	free(it);
}

static struct s3erofs_object_info *
s3erofs_get_next_object(struct s3erofs_object_iterator *it)
{
	int ret;

	if (it->objects && it->objects[it->cur].key)
		return &it->objects[it->cur++];

	if (it->is_truncated) {
		ret = s3erofs_list_objects(it);
		if (ret < 0)
			return ERR_PTR(ret);
		return &it->objects[it->cur++];
	}
	return NULL;
}

static int s3erofs_curl_easy_init(struct erofs_s3 *s3)
{
	CURL *curl;

	curl = curl_easy_init();
	if (!curl)
		return -ENOMEM;

	if (curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK)
		goto out_cleanup;

	if (curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L) != CURLE_OK)
		goto out_cleanup;

	if (curl_easy_setopt(curl, CURLOPT_USERAGENT,
			     "s3erofs/" PACKAGE_VERSION) != CURLE_OK)
		goto out_cleanup;

	s3->easy_curl = curl;
	return 0;
out_cleanup:
	curl_easy_cleanup(curl);
	return -EFAULT;
}

static void s3erofs_curl_easy_exit(struct erofs_s3 *s3)
{
	if (!s3->easy_curl)
		return;
	curl_easy_cleanup(s3->easy_curl);
	s3->easy_curl = NULL;
}

struct s3erofs_curl_getobject_resp {
	struct erofs_vfile *vf;
	erofs_off_t pos, end;
};

static size_t s3erofs_remote_getobject_cb(void *contents, size_t size,
					  size_t nmemb, void *userp)
{
	struct s3erofs_curl_getobject_resp *resp = userp;
	size_t realsize = size * nmemb;

	if (resp->pos + realsize > resp->end ||
	    erofs_io_pwrite(resp->vf, contents, resp->pos, realsize) != realsize)
		return 0;

	resp->pos += realsize;
	return realsize;
}

static int s3erofs_remote_getobject(struct erofs_importer *im,
				    struct erofs_s3 *s3,
				    struct erofs_inode *inode,
				    const char *bucket, const char *key)
{
	struct erofs_sb_info *sbi = inode->sbi;
	struct s3erofs_curl_request req = {};
	struct s3erofs_curl_getobject_resp resp;
	struct erofs_vfile vf;
	int ret;

	ret = s3erofs_prepare_url(&req, s3->endpoint, bucket, key, NULL,
				  s3->url_style, s3->sig);
	if (ret < 0)
		return ret;

	if (curl_easy_setopt(s3->easy_curl, CURLOPT_WRITEFUNCTION,
			     s3erofs_remote_getobject_cb) != CURLE_OK)
		return -EIO;

	resp.pos = 0;
	if (!cfg.c_compr_opts[0].alg && im->params->no_datainline) {
		inode->datalayout = EROFS_INODE_FLAT_PLAIN;
		inode->idata_size = 0;
		ret = erofs_allocate_inode_bh_data(inode,
				DIV_ROUND_UP(inode->i_size, 1U << sbi->blkszbits));
		if (ret)
			return ret;
		resp.vf = &sbi->bdev;
		resp.pos = erofs_pos(inode->sbi, inode->u.i_blkaddr);
		inode->datasource = EROFS_INODE_DATA_SOURCE_NONE;
	} else {
		u64 off;

		if (!inode->i_diskbuf) {
			inode->i_diskbuf = calloc(1, sizeof(*inode->i_diskbuf));
			if (!inode->i_diskbuf)
				return -ENOSPC;
		} else {
			erofs_diskbuf_close(inode->i_diskbuf);
		}

		vf = (struct erofs_vfile) {.fd =
			erofs_diskbuf_reserve(inode->i_diskbuf, 0, &off)};
		if (vf.fd < 0)
			return -EBADF;
		resp.pos = off;
		resp.vf = &vf;
		inode->datasource = EROFS_INODE_DATA_SOURCE_DISKBUF;
	}
	resp.end = resp.pos + inode->i_size;

	ret = s3erofs_request_perform(s3, &req, &resp);
	if (resp.vf == &vf) {
		erofs_diskbuf_commit(inode->i_diskbuf, resp.end - resp.pos);
		if (ret) {
			erofs_diskbuf_close(inode->i_diskbuf);
			inode->i_diskbuf = NULL;
			inode->datasource = EROFS_INODE_DATA_SOURCE_NONE;
		}
	}
	if (ret)
		return ret;
	return resp.pos != resp.end ? -EIO : 0;
}

int s3erofs_build_trees(struct erofs_importer *im, struct erofs_s3 *s3,
			const char *path, bool fillzero)
{
	struct erofs_sb_info *sbi = im->sbi;
	struct erofs_inode *root = im->root;
	struct s3erofs_object_iterator *iter;
	struct s3erofs_object_info *obj;
	struct erofs_dentry *d;
	struct erofs_inode *inode;
	struct stat st;
	char *trimmed;
	bool dumb;
	int ret;

	st.st_uid = root->i_uid;
	st.st_gid = root->i_gid;

	ret = s3erofs_curl_easy_init(s3);
	if (ret) {
		erofs_err("failed to initialize s3erofs: %s", erofs_strerror(ret));
		return ret;
	}

	iter = s3erofs_create_object_iterator(s3, path, NULL);
	if (IS_ERR(iter)) {
		erofs_err("failed to create object iterator");
		ret = PTR_ERR(iter);
		goto err_global;
	}

	while (1) {
		obj = s3erofs_get_next_object(iter);
		if (!obj) {
			break;
		} else if (IS_ERR(obj)) {
			erofs_err("failed to get next object");
			ret = PTR_ERR(obj);
			goto err_iter;
		}

		d = erofs_rebuild_get_dentry(root, obj->key, false,
					     &dumb, &dumb, false);
		if (IS_ERR(d)) {
			ret = PTR_ERR(d);
			goto err_iter;
		}
		if (d->type == EROFS_FT_DIR) {
			inode = d->inode;
			inode->i_mode = S_IFDIR | 0755;
		} else {
			inode = erofs_new_inode(sbi);
			if (IS_ERR(inode)) {
				ret = PTR_ERR(inode);
				goto err_iter;
			}

			inode->i_mode = S_IFREG | 0644;
			inode->i_parent = d->inode;
			inode->i_nlink = 1;

			d->inode = inode;
			d->type = EROFS_FT_REG_FILE;
		}
		inode->i_srcpath = strdup(obj->key);
		if (!inode->i_srcpath) {
			ret = -ENOMEM;
			goto err_iter;
		}

		trimmed = erofs_trim_for_progressinfo(inode->i_srcpath,
				sizeof("Importing  ...") - 1);
		erofs_update_progressinfo("Importing %s ...", trimmed);
		free(trimmed);

		st.st_mtime = obj->mtime;
		ST_MTIM_NSEC_SET(&st, obj->mtime_ns);
		ret = __erofs_fill_inode(im, inode, &st, obj->key);
		if (!ret && S_ISREG(inode->i_mode)) {
			inode->i_size = obj->size;
			if (fillzero)
				ret = erofs_write_zero_inode(inode);
			else
				ret = s3erofs_remote_getobject(im, s3, inode,
						iter->bucket, obj->key);
		}
		if (ret)
			goto err_iter;
	}

err_iter:
	s3erofs_destroy_object_iterator(iter);
err_global:
	s3erofs_curl_easy_exit(s3);
	return ret;
}

#ifdef TEST
struct s3erofs_prepare_url_testcase {
	const char *name;
	const char *endpoint;
	const char *path;
	const char *key;
	enum s3erofs_url_style url_style;
	const char *expected_url;
	const char *expected_canonical_v2;
	const char *expected_canonical_v4;
	int expected_ret;
};

static bool run_s3erofs_prepare_url_test(const struct s3erofs_prepare_url_testcase *tc,
					 enum s3erofs_signature_version sig)
{
	struct s3erofs_curl_request req = {};
	int ret;
	const char *expected_canonical;

	printf("Running test: %s\n", tc->name);

	ret = s3erofs_prepare_url(&req, tc->endpoint, tc->path, tc->key, NULL,
				  tc->url_style, sig);

	if (ret != tc->expected_ret) {
		printf("  FAILED: expected return %d, got %d\n", tc->expected_ret, ret);
		return false;
	}

	if (ret < 0) {
		printf("  PASSED (expected error)\n");
		return true;
	}

	if (tc->expected_url && strcmp(req.url, tc->expected_url) != 0) {
		printf("  FAILED: URL mismatch\n");
		printf("    Expected: %s\n", tc->expected_url);
		printf("    Got:      %s\n", req.url);
		return false;
	}

	expected_canonical = (sig == S3EROFS_SIGNATURE_VERSION_2 ?
					    tc->expected_canonical_v2 :
					    tc->expected_canonical_v4);
	if (expected_canonical && strcmp(req.canonical_uri, expected_canonical) != 0) {
		printf("  FAILED: Canonical uri mismatch\n");
		printf("    Expected: %s\n", expected_canonical);
		printf("    Got:      %s\n", req.canonical_uri);
		return false;
	}

	printf("  PASSED\n");
	printf("    URL: %s\n", req.url);
	printf("    Canonical: %s\n", req.canonical_uri);
	return true;
}

static bool test_s3erofs_prepare_url(void)
{
	struct s3erofs_prepare_url_testcase tests[] = {
		{
			.name = "Virtual-hosted style with https",
			.endpoint = "s3.amazonaws.com",
			.path = "my-bucket",
			.key = "path/to/object.txt",
			.url_style = S3EROFS_URL_STYLE_VIRTUAL_HOST,
			.expected_url =
				"https://my-bucket.s3.amazonaws.com/path/to/object.txt",
			.expected_canonical_v2 = "/my-bucket/path/to/object.txt",
			.expected_canonical_v4 = "/path/to/object.txt",
			.expected_ret = 0,
		},
		{
			.name = "Path style with https",
			.endpoint = "s3.amazonaws.com",
			.path = "my-bucket",
			.key = "path/to/object.txt",
			.url_style = S3EROFS_URL_STYLE_PATH,
			.expected_url =
				"https://s3.amazonaws.com/my-bucket/path/to/object.txt",
			.expected_canonical_v2 = "/my-bucket/path/to/object.txt",
			.expected_canonical_v4 = "/my-bucket/path/to/object.txt",
			.expected_ret = 0,
		},
		{
			.name = "Virtual-hosted with explicit https://",
			.endpoint = "https://s3.us-west-2.amazonaws.com",
			.path = "test-bucket",
			.key = "file.bin",
			.url_style = S3EROFS_URL_STYLE_VIRTUAL_HOST,
			.expected_url =
				"https://test-bucket.s3.us-west-2.amazonaws.com/file.bin",
			.expected_canonical_v2 = "/test-bucket/file.bin",
			.expected_canonical_v4 = "/file.bin",
			.expected_ret = 0,
		},
		{
			.name = "Path style with explicit http://",
			.endpoint = "http://localhost:9000",
			.path = "local-bucket",
			.key = "data/file.dat",
			.url_style = S3EROFS_URL_STYLE_PATH,
			.expected_url =
				"http://localhost:9000/local-bucket/data/file.dat",
			.expected_canonical_v2 = "/local-bucket/data/file.dat",
			.expected_canonical_v4 = "/local-bucket/data/file.dat",
			.expected_ret = 0,
		},
		{
			.name = "Virtual-hosted style with key ends with slash",
			.endpoint = "http://localhost:9000",
			.path = "local-bucket",
			.key = "data/file.dat/",
			.url_style = S3EROFS_URL_STYLE_VIRTUAL_HOST,
			.expected_url =
				"http://local-bucket.localhost:9000/data/file.dat/",
			.expected_canonical_v2 = "/local-bucket/data/file.dat/",
			.expected_canonical_v4 = "/data/file.dat/",
			.expected_ret = 0,
		},
		{
			.name = "Path style with key ends with slash",
			.endpoint = "http://localhost:9000",
			.path = "local-bucket",
			.key = "data/file.dat/",
			.url_style = S3EROFS_URL_STYLE_PATH,
			.expected_url =
				"http://localhost:9000/local-bucket/data/file.dat/",
			.expected_canonical_v2 = "/local-bucket/data/file.dat/",
			.expected_canonical_v4 = "/local-bucket/data/file.dat/",
			.expected_ret = 0,
		},
		{
			.name = "Virtual-hosted without key",
			.endpoint = "s3.amazonaws.com",
			.path = "my-bucket",
			.key = NULL,
			.url_style = S3EROFS_URL_STYLE_VIRTUAL_HOST,
			.expected_url = "https://my-bucket.s3.amazonaws.com/",
			.expected_canonical_v2 = "/my-bucket/",
			.expected_canonical_v4 = "/",
			.expected_ret = 0,
		},
		{
			.name = "Path style without key",
			.endpoint = "s3.amazonaws.com",
			.path = "my-bucket",
			.key = NULL,
			.url_style = S3EROFS_URL_STYLE_PATH,
			.expected_url = "https://s3.amazonaws.com/my-bucket",
			.expected_canonical_v2 = "/my-bucket",
			.expected_canonical_v4 = "/my-bucket",
			.expected_ret = 0,
		},
		{
			.name = "Path style bucket ending with slash without key",
			.endpoint = "s3.amazonaws.com",
			.path = "bucket/",
			.key = NULL,
			.url_style = S3EROFS_URL_STYLE_PATH,
			.expected_url = "https://s3.amazonaws.com/bucket/",
			.expected_canonical_v2 = "/bucket/",
			.expected_canonical_v4 = "/bucket/",
			.expected_ret = 0,
		},
		{
			.name = "Virtual-hosted bucket ending with slash without key",
			.endpoint = "s3.amazonaws.com",
			.path = "bucket/",
			.key = NULL,
			.url_style = S3EROFS_URL_STYLE_VIRTUAL_HOST,
			.expected_url = "https://bucket.s3.amazonaws.com/",
			.expected_canonical_v2 = "/bucket/",
			.expected_canonical_v4 = "/",
			.expected_ret = 0,
		},
		{
			.name = "Path style bucket ending with slash",
			.endpoint = "s3.amazonaws.com",
			.path = "bucket/",
			.key = "object.txt",
			.url_style = S3EROFS_URL_STYLE_PATH,
			.expected_url = "https://s3.amazonaws.com/bucket/object.txt",
			.expected_canonical_v2 = "/bucket/object.txt",
			.expected_canonical_v4 = "/bucket/object.txt",
			.expected_ret = 0,
		},
		{
			.name = "Virtual-hosted bucket ending with slash",
			.endpoint = "s3.amazonaws.com",
			.path = "bucket/",
			.key = "object.txt",
			.url_style = S3EROFS_URL_STYLE_VIRTUAL_HOST,
			.expected_url = "https://bucket.s3.amazonaws.com/object.txt",
			.expected_canonical_v2 = "/bucket/object.txt",
			.expected_canonical_v4 = "/object.txt",
			.expected_ret = 0,
		},
		{
			.name = "Path style bucket ending with slash key with slash",
			.endpoint = "s3.amazonaws.com",
			.path = "bucket/",
			.key = "a/b/c/object.txt",
			.url_style = S3EROFS_URL_STYLE_PATH,
			.expected_url = "https://s3.amazonaws.com/bucket/a/b/c/object.txt",
			.expected_canonical_v2 = "/bucket/a/b/c/object.txt",
			.expected_canonical_v4 = "/bucket/a/b/c/object.txt",
			.expected_ret = 0,
		},
		{
			.name = "Virtual-hosted bucket ending with slash key with slash",
			.endpoint = "s3.amazonaws.com",
			.path = "bucket/",
			.key = "a/b/c/object.txt",
			.url_style = S3EROFS_URL_STYLE_VIRTUAL_HOST,
			.expected_url = "https://bucket.s3.amazonaws.com/a/b/c/object.txt",
			.expected_canonical_v2 = "/bucket/a/b/c/object.txt",
			.expected_canonical_v4 = "/a/b/c/object.txt",
			.expected_ret = 0,
		},
		{
			.name = "Error: NULL endpoint",
			.endpoint = NULL,
			.path = "my-bucket",
			.key = "file.txt",
			.url_style = S3EROFS_URL_STYLE_PATH,
			.expected_url = NULL,
			.expected_canonical_v2 = NULL,
			.expected_canonical_v4 = NULL,
			.expected_ret = -EINVAL,
		},
		{
			.name = "Error: NULL bucket",
			.endpoint = "s3.amazonaws.com",
			.path = NULL,
			.key = "file.txt",
			.url_style = S3EROFS_URL_STYLE_PATH,
			.expected_url = NULL,
			.expected_canonical_v2 = NULL,
			.expected_canonical_v4 = NULL,
			.expected_ret = -EINVAL,
		},
		{
			.name = "Key with special characters",
			.endpoint = "s3.amazonaws.com",
			.path = "bucket",
			.key = "path/to/file-name_v2.0.txt",
			.url_style = S3EROFS_URL_STYLE_VIRTUAL_HOST,
			.expected_url =
				"https://bucket.s3.amazonaws.com/path/to/file-name_v2.0.txt",
			.expected_canonical_v2 = "/bucket/path/to/file-name_v2.0.txt",
			.expected_canonical_v4 = "/path/to/file-name_v2.0.txt",
			.expected_ret = 0,
		}
	};
	int i;
	int pass = 0;

	for (i = 0; i < ARRAY_SIZE(tests); ++i) {
		pass += run_s3erofs_prepare_url_test(&tests[i], S3EROFS_SIGNATURE_VERSION_2);
		putc('\n', stdout);
		pass += run_s3erofs_prepare_url_test(&tests[i], S3EROFS_SIGNATURE_VERSION_4);
		putc('\n', stdout);
	}

	printf("Run all %d tests with %d PASSED\n", 2 * i, pass);
	return 2 * ARRAY_SIZE(tests) == pass;
}

int main(int argc, char *argv[])
{
	exit(test_s3erofs_prepare_url() ? EXIT_SUCCESS : EXIT_FAILURE);
}
#endif
