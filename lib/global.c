// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2025 Alibaba Cloud
 */
#include "erofs/lock.h"
#ifdef HAVE_CURL_CURL_H
#include <curl/curl.h>
#endif
#ifdef HAVE_LIBXML_PARSER_H
#include <libxml/parser.h>
#endif
#include "erofs/err.h"
#include "erofs/config.h"

static EROFS_DEFINE_MUTEX(erofs_global_mutex);
#ifdef HAVE_LIBCURL
static bool erofs_global_curl_initialized;
#endif

int liberofs_global_init(void)
{
	int err = 0;

	erofs_mutex_lock(&erofs_global_mutex);
	erofs_init_configure();
#ifdef S3EROFS_ENABLED
	xmlInitParser();
#endif
#ifdef HAVE_LIBCURL
	if (!erofs_global_curl_initialized) {
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
			err = -EFAULT;
			goto out_unlock;
		}
		erofs_global_curl_initialized = true;
	}
out_unlock:
#endif
	erofs_mutex_unlock(&erofs_global_mutex);
	return err;
}

void liberofs_global_exit(void)
{
	erofs_mutex_lock(&erofs_global_mutex);
#ifdef HAVE_LIBCURL
	if (erofs_global_curl_initialized) {
		curl_global_cleanup();
		erofs_global_curl_initialized = false;
	}
#endif
#ifdef S3EROFS_ENABLED
	xmlCleanupParser();
#endif
	erofs_exit_configure();
	erofs_mutex_unlock(&erofs_global_mutex);
}
