// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2019 Li Guifu <blucerlee@gmail.com>
 *                    Gao Xiang <xiang@kernel.org>
 * Copyright (C) 2025 Alibaba Cloud
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/xattr.h>
#ifdef HAVE_LINUX_XATTR_H
#include <linux/xattr.h>
#endif
#include <sys/stat.h>
#include <dirent.h>
#include "erofs/print.h"
#include "erofs/list.h"
#include "erofs/xattr.h"
#include "erofs/fragments.h"
#include "erofs/importer.h"
#include "liberofs_cache.h"
#include "liberofs_metabox.h"
#include "liberofs_xxhash.h"
#include "liberofs_private.h"

#ifndef XATTR_SYSTEM_PREFIX
#define XATTR_SYSTEM_PREFIX	"system."
#endif
#ifndef XATTR_SYSTEM_PREFIX_LEN
#define XATTR_SYSTEM_PREFIX_LEN (sizeof(XATTR_SYSTEM_PREFIX) - 1)
#endif
#ifndef XATTR_USER_PREFIX
#define XATTR_USER_PREFIX	"user."
#endif
#ifndef XATTR_USER_PREFIX_LEN
#define XATTR_USER_PREFIX_LEN (sizeof(XATTR_USER_PREFIX) - 1)
#endif
#ifndef XATTR_SECURITY_PREFIX
#define XATTR_SECURITY_PREFIX	"security."
#endif
#ifndef XATTR_SECURITY_PREFIX_LEN
#define XATTR_SECURITY_PREFIX_LEN (sizeof(XATTR_SECURITY_PREFIX) - 1)
#endif
#ifndef XATTR_TRUSTED_PREFIX
#define XATTR_TRUSTED_PREFIX	"trusted."
#endif
#ifndef XATTR_TRUSTED_PREFIX_LEN
#define XATTR_TRUSTED_PREFIX_LEN (sizeof(XATTR_TRUSTED_PREFIX) - 1)
#endif
#ifndef XATTR_NAME_POSIX_ACL_ACCESS
#define XATTR_NAME_POSIX_ACL_ACCESS "system.posix_acl_access"
#endif
#ifndef XATTR_NAME_POSIX_ACL_DEFAULT
#define XATTR_NAME_POSIX_ACL_DEFAULT "system.posix_acl_default"
#endif
#ifndef XATTR_NAME_SECURITY_SELINUX
#define XATTR_NAME_SECURITY_SELINUX "security.selinux"
#endif
#ifndef XATTR_NAME_SECURITY_CAPABILITY
#define XATTR_NAME_SECURITY_CAPABILITY "security.capability"
#endif
#ifndef OVL_XATTR_NAMESPACE
#define OVL_XATTR_NAMESPACE "overlay."
#endif
#ifndef OVL_XATTR_OPAQUE_POSTFIX
#define OVL_XATTR_OPAQUE_POSTFIX "opaque"
#endif
#ifndef OVL_XATTR_ORIGIN_POSTFIX
#define OVL_XATTR_ORIGIN_POSTFIX "origin"
#endif
#ifndef OVL_XATTR_TRUSTED_PREFIX
#define OVL_XATTR_TRUSTED_PREFIX XATTR_TRUSTED_PREFIX OVL_XATTR_NAMESPACE
#endif
#ifndef OVL_XATTR_OPAQUE
#define OVL_XATTR_OPAQUE OVL_XATTR_TRUSTED_PREFIX OVL_XATTR_OPAQUE_POSTFIX
#endif
#ifndef OVL_XATTR_ORIGIN
#define OVL_XATTR_ORIGIN OVL_XATTR_TRUSTED_PREFIX OVL_XATTR_ORIGIN_POSTFIX
#endif

static ssize_t erofs_sys_llistxattr(const char *path, char *list, size_t size)
{
#ifdef HAVE_LLISTXATTR
	return llistxattr(path, list, size);
#elif defined(__APPLE__)
	return listxattr(path, list, size, XATTR_NOFOLLOW);
#endif
	return 0;
}

static ssize_t erofs_sys_lgetxattr(const char *path, const char *name,
				   void *value, size_t size)
{
#ifdef HAVE_LGETXATTR
	return lgetxattr(path, name, value, size);
#elif defined(__APPLE__)
	return getxattr(path, name, value, size, 0, XATTR_NOFOLLOW);
#endif
	errno = ENODATA;
	return -1;
}

/* one extra byte for the trailing `\0` of attribute name */
#define EROFS_XATTR_KSIZE(kvlen)	(kvlen[0] + 1)
#define EROFS_XATTR_KVSIZE(kvlen)	(EROFS_XATTR_KSIZE(kvlen) + kvlen[1])

/*
 * @base_index:	the index of the matched predefined short prefix
 * @prefix:	the index of the matched long prefix, if any;
 *		same as base_index otherwise
 * @prefix_len:	the length of the matched long prefix if any;
 *		the length of the matched predefined short prefix otherwise
 */
struct erofs_xattritem {
	struct list_head node;
	struct erofs_xattritem *next_shared_xattr;
	const char *kvbuf;
	unsigned int hash[2], len[2], count;
	int shared_xattr_id;
	unsigned int prefix, base_index, prefix_len;
};

struct erofs_inode_xattr_node {
	struct list_head list;
	struct erofs_xattritem *item;
};

struct erofs_xattrmgr {
	struct list_head hash[1 << 14];
	struct erofs_xattritem *shared_xattrs;
	unsigned int sharedxattr_count;
};

int erofs_xattr_init(struct erofs_sb_info *sbi)
{
	struct erofs_xattrmgr *xamgr = sbi->xamgr;
	unsigned int i;

	if (xamgr)
		return 0;

	xamgr = malloc(sizeof(struct erofs_xattrmgr));
	if (!xamgr)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(xamgr->hash); ++i)
		init_list_head(&xamgr->hash[i]);
	sbi->xamgr = xamgr;
	return 0;
}

static struct erofs_xattr_prefix {
	const char *prefix;
	unsigned int prefix_len;
} xattr_types[] = {
	[EROFS_XATTR_INDEX_USER] = {
		XATTR_USER_PREFIX,
		XATTR_USER_PREFIX_LEN
	}, [EROFS_XATTR_INDEX_POSIX_ACL_ACCESS] = {
		XATTR_NAME_POSIX_ACL_ACCESS,
		sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1
	}, [EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT] = {
		XATTR_NAME_POSIX_ACL_DEFAULT,
		sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1
	}, [EROFS_XATTR_INDEX_TRUSTED] = {
		XATTR_TRUSTED_PREFIX,
		XATTR_TRUSTED_PREFIX_LEN
	}, [EROFS_XATTR_INDEX_SECURITY] = {
		XATTR_SECURITY_PREFIX,
		XATTR_SECURITY_PREFIX_LEN
	}
};

struct ea_type_node {
	struct list_head list;
	struct erofs_xattr_prefix type;
	unsigned int index, base_index, base_len;
};

static LIST_HEAD(ea_name_prefixes);
static unsigned int ea_prefix_count;

bool erofs_xattr_prefix_matches(const char *key, unsigned int *index,
				unsigned int *len)
{
	struct erofs_xattr_prefix *p;

	*index = 0;
	*len = 0;
	for (p = xattr_types; p < xattr_types + ARRAY_SIZE(xattr_types); ++p) {
		if (p->prefix && !strncmp(p->prefix, key, p->prefix_len)) {
			*len = p->prefix_len;
			*index = p - xattr_types;
			return true;
		}
	}
	return false;
}

static unsigned int BKDRHash(char *str, unsigned int len)
{
	const unsigned int seed = 131313;
	unsigned int hash = 0;

	while (len) {
		hash = hash * seed + (*str++);
		--len;
	}
	return hash;
}

static unsigned int put_xattritem(struct erofs_xattritem *item)
{
	if (item->count > 1)
		return --item->count;
	list_del(&item->node);
	free((void *)item->kvbuf);
	free(item);
	return 0;
}

static struct erofs_xattritem *get_xattritem(struct erofs_sb_info *sbi,
					     char *kvbuf, unsigned int len[2])
{
	struct erofs_xattrmgr *xamgr = sbi->xamgr;
	struct erofs_xattritem *item;
	struct ea_type_node *tnode;
	struct list_head *head;
	unsigned int hash[2], hkey;

	hash[0] = BKDRHash(kvbuf, len[0]);
	hash[1] = BKDRHash(kvbuf + EROFS_XATTR_KSIZE(len), len[1]);
	hkey = (hash[0] ^ hash[1]) & (ARRAY_SIZE(xamgr->hash) - 1);
	head = xamgr->hash + hkey;
	list_for_each_entry(item, head, node) {
		if (item->len[0] == len[0] && item->len[1] == len[1] &&
		    item->hash[0] == hash[0] && item->hash[1] == hash[1] &&
		    !memcmp(kvbuf, item->kvbuf, EROFS_XATTR_KVSIZE(len))) {
			free(kvbuf);
			++item->count;
			return item;
		}
	}

	item = malloc(sizeof(*item));
	if (!item)
		return ERR_PTR(-ENOMEM);

	(void)erofs_xattr_prefix_matches(kvbuf, &item->base_index,
					 &item->prefix_len);
	DBG_BUGON(len[0] < item->prefix_len);
	init_list_head(&item->node);
	item->count = 1;
	item->kvbuf = kvbuf;
	item->len[0] = len[0];
	item->len[1] = len[1];
	item->hash[0] = hash[0];
	item->hash[1] = hash[1];
	item->shared_xattr_id = -1;
	item->prefix = item->base_index;

	list_for_each_entry(tnode, &ea_name_prefixes, list) {
		if (item->base_index == tnode->base_index &&
		    !strncmp(tnode->type.prefix, kvbuf,
			     tnode->type.prefix_len)) {
			item->prefix = tnode->index;
			item->prefix_len = tnode->type.prefix_len;
			break;
		}
	}
	list_add(&item->node, head);
	return item;
}

static struct erofs_xattritem *parse_one_xattr(struct erofs_sb_info *sbi,
					       const char *path, const char *key,
					       unsigned int keylen)
{
	ssize_t ret;
	struct erofs_xattritem *item;
	unsigned int len[2];
	char *kvbuf;

	erofs_dbg("parse xattr [%s] of %s", path, key);

	/* length of the key */
	len[0] = keylen;

	/* determine length of the value */
	ret = erofs_sys_lgetxattr(path, key, NULL, 0);
	if (ret < 0)
		return ERR_PTR(-errno);
	len[1] = ret;

	/* allocate key-value buffer */
	kvbuf = malloc(EROFS_XATTR_KVSIZE(len));
	if (!kvbuf)
		return ERR_PTR(-ENOMEM);
	memcpy(kvbuf, key, EROFS_XATTR_KSIZE(len));
	if (len[1]) {
		/* copy value to buffer */
		ret = erofs_sys_lgetxattr(path, key,
					  kvbuf + EROFS_XATTR_KSIZE(len),
					  len[1]);
		if (ret < 0) {
			ret = -errno;
			goto out;
		}
		if (len[1] != ret) {
			erofs_warn("size of xattr value got changed just now (%u-> %ld)",
				  len[1], (long)ret);
			len[1] = ret;
		}
	}

	item = get_xattritem(sbi, kvbuf, len);
	if (!IS_ERR(item))
		return item;
	ret = PTR_ERR(item);
out:
	free(kvbuf);
	return ERR_PTR(ret);
}

static struct erofs_xattritem *erofs_get_selabel_xattr(struct erofs_sb_info *sbi,
						       const char *srcpath,
						       mode_t mode)
{
#ifdef HAVE_LIBSELINUX
	if (cfg.sehnd) {
		char *secontext;
		int ret;
		unsigned int len[2];
		char *kvbuf, *fspath;
		struct erofs_xattritem *item;

		if (cfg.mount_point)
			ret = asprintf(&fspath, "/%s/%s", cfg.mount_point,
				       erofs_fspath(srcpath));
		else
			ret = asprintf(&fspath, "/%s", erofs_fspath(srcpath));
		if (ret <= 0)
			return ERR_PTR(-ENOMEM);

		ret = selabel_lookup(cfg.sehnd, &secontext, fspath, mode);
		free(fspath);

		if (ret) {
			ret = -errno;
			if (ret != -ENOENT) {
				erofs_err("failed to lookup selabel for %s: %s",
					  srcpath, erofs_strerror(ret));
				return ERR_PTR(ret);
			}
			/* secontext = "u:object_r:unlabeled:s0"; */
			return NULL;
		}

		len[0] = sizeof(XATTR_NAME_SECURITY_SELINUX) - 1;
		len[1] = strlen(secontext);
		kvbuf = malloc(EROFS_XATTR_KVSIZE(len));
		if (!kvbuf) {
			freecon(secontext);
			return ERR_PTR(-ENOMEM);
		}
		sprintf(kvbuf, "%s", XATTR_NAME_SECURITY_SELINUX);
		memcpy(kvbuf + EROFS_XATTR_KSIZE(len), secontext, len[1]);
		freecon(secontext);
		item = get_xattritem(sbi, kvbuf, len);
		if (IS_ERR(item))
			free(kvbuf);
		return item;
	}
#endif
	return NULL;
}

static int inode_xattr_add(struct list_head *hlist, struct erofs_xattritem *item)
{
	struct erofs_inode_xattr_node *node = malloc(sizeof(*node));

	if (!node)
		return -ENOMEM;
	init_list_head(&node->list);
	node->item = item;
	list_add(&node->list, hlist);
	return 0;
}

static int erofs_xattr_add(struct erofs_sb_info *sbi, struct list_head *ixattrs,
			   struct erofs_xattritem *item)
{
	struct erofs_xattrmgr *xamgr = sbi->xamgr;

	if (ixattrs)
		return inode_xattr_add(ixattrs, item);

	if (item->count == cfg.c_inline_xattr_tolerance + 1) {
		item->next_shared_xattr = xamgr->shared_xattrs;
		xamgr->shared_xattrs = item;
		++xamgr->sharedxattr_count;
	}
	return 0;
}

static bool erofs_is_skipped_xattr(const char *key)
{
#ifdef HAVE_LIBSELINUX
	/* if sehnd is valid, selabels will be overridden */
	if (cfg.sehnd && !strcmp(key, XATTR_SECURITY_PREFIX "selinux"))
		return true;
#endif
	return false;
}

static int read_xattrs_from_file(struct erofs_sb_info *sbi, const char *path,
				 mode_t mode, struct list_head *ixattrs)
{
	ssize_t kllen = erofs_sys_llistxattr(path, NULL, 0);
	char *keylst, *key, *klend;
	unsigned int keylen;
	struct erofs_xattritem *item;
	int ret;

	if (kllen < 0 && errno != ENODATA && errno != EOPNOTSUPP) {
		erofs_err("failed to get the size of the xattr list for %s: %s",
			  path, strerror(errno));
		return -errno;
	}

	ret = 0;
	if (kllen <= 1)
		goto out;

	keylst = malloc(kllen);
	if (!keylst)
		return -ENOMEM;

	/* copy the list of attribute keys to the buffer.*/
	kllen = erofs_sys_llistxattr(path, keylst, kllen);
	if (kllen < 0) {
		erofs_err("llistxattr to get names for %s failed", path);
		ret = -errno;
		goto err;
	}

	/*
	 * loop over the list of zero terminated strings with the
	 * attribute keys. Use the remaining buffer length to determine
	 * the end of the list.
	 */
	klend = keylst + kllen;
	ret = 0;

	for (key = keylst; key != klend; key += keylen + 1) {
		keylen = strlen(key);
		if (erofs_is_skipped_xattr(key))
			continue;

		item = parse_one_xattr(sbi, path, key, keylen);
		/* skip inaccessible xattrs */
		if (item == ERR_PTR(-ENODATA) || !item) {
			erofs_warn("skipped inaccessible xattr %s in %s",
				   key, path);
			continue;
		}
		if (IS_ERR(item)) {
			ret = PTR_ERR(item);
			goto err;
		}

		ret = erofs_xattr_add(sbi, ixattrs, item);
		if (ret < 0)
			goto err;
	}
	free(keylst);

out:
	/* if some selabel is avilable, need to add right now */
	item = erofs_get_selabel_xattr(sbi, path, mode);
	if (IS_ERR(item))
		return PTR_ERR(item);
	if (item)
		ret = erofs_xattr_add(sbi, ixattrs, item);
	return ret;

err:
	free(keylst);
	return ret;
}

int erofs_setxattr(struct erofs_inode *inode, char *key,
		   const void *value, size_t size)
{
	struct erofs_sb_info *sbi = inode->sbi;
	char *kvbuf;
	unsigned int len[2];
	struct erofs_xattritem *item;

	len[0] = strlen(key);
	len[1] = size;

	kvbuf = malloc(EROFS_XATTR_KVSIZE(len));
	if (!kvbuf)
		return -ENOMEM;

	memcpy(kvbuf, key, EROFS_XATTR_KSIZE(len));
	memcpy(kvbuf + EROFS_XATTR_KSIZE(len), value, size);

	item = get_xattritem(sbi, kvbuf, len);
	if (IS_ERR(item)) {
		free(kvbuf);
		return PTR_ERR(item);
	}
	DBG_BUGON(!item);

	return erofs_xattr_add(sbi, &inode->i_xattrs, item);
}

static void erofs_removexattr(struct erofs_inode *inode, const char *key)
{
	struct erofs_inode_xattr_node *node, *n;

	list_for_each_entry_safe(node, n, &inode->i_xattrs, list) {
		if (!strcmp(node->item->kvbuf, key)) {
			list_del(&node->list);
			put_xattritem(node->item);
			free(node);
		}
	}
}

int erofs_set_opaque_xattr(struct erofs_inode *inode)
{
	return erofs_setxattr(inode, OVL_XATTR_OPAQUE, "y", 1);
}

void erofs_clear_opaque_xattr(struct erofs_inode *inode)
{
	erofs_removexattr(inode, OVL_XATTR_OPAQUE);
}

int erofs_set_origin_xattr(struct erofs_inode *inode)
{
	return erofs_setxattr(inode, OVL_XATTR_ORIGIN, NULL, 0);
}

#ifdef WITH_ANDROID
static int erofs_droid_xattr_set_caps(struct erofs_inode *inode)
{
	struct erofs_sb_info *sbi = inode->sbi;
	const u64 capabilities = inode->capabilities;
	char *kvbuf;
	unsigned int len[2];
	struct vfs_cap_data caps;
	struct erofs_xattritem *item;

	if (!capabilities)
		return 0;

	len[0] = sizeof(XATTR_NAME_SECURITY_CAPABILITY) - 1;
	len[1] = sizeof(caps);

	kvbuf = malloc(EROFS_XATTR_KVSIZE(len));
	if (!kvbuf)
		return -ENOMEM;

	sprintf(kvbuf, "%s", XATTR_NAME_SECURITY_CAPABILITY);
	caps.magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE;
	caps.data[0].permitted = (u32) capabilities;
	caps.data[0].inheritable = 0;
	caps.data[1].permitted = (u32) (capabilities >> 32);
	caps.data[1].inheritable = 0;
	memcpy(kvbuf + EROFS_XATTR_KSIZE(len), &caps, len[1]);

	item = get_xattritem(sbi, kvbuf, len);
	if (IS_ERR(item)) {
		free(kvbuf);
		return PTR_ERR(item);
	}
	DBG_BUGON(!item);

	return erofs_xattr_add(sbi, &inode->i_xattrs, item);
}
#else
static int erofs_droid_xattr_set_caps(struct erofs_inode *inode)
{
	return 0;
}
#endif

int erofs_scan_file_xattrs(struct erofs_inode *inode)
{
	int ret;
	struct list_head *ixattrs = &inode->i_xattrs;

	/* check if xattr is disabled */
	if (cfg.c_inline_xattr_tolerance < 0)
		return 0;

	ret = read_xattrs_from_file(inode->sbi, inode->i_srcpath,
				    inode->i_mode, ixattrs);
	if (ret < 0)
		return ret;

	return erofs_droid_xattr_set_caps(inode);
}

int erofs_read_xattrs_from_disk(struct erofs_inode *inode)
{
	ssize_t kllen;
	char *keylst, *key;
	int ret;

	init_list_head(&inode->i_xattrs);
	kllen = erofs_listxattr(inode, NULL, 0);
	if (kllen < 0)
		return kllen;
	if (kllen <= 1)
		return 0;

	keylst = malloc(kllen);
	if (!keylst)
		return -ENOMEM;

	ret = erofs_listxattr(inode, keylst, kllen);
	if (ret < 0)
		goto out;

	for (key = keylst; key < keylst + kllen; key += strlen(key) + 1) {
		void *value = NULL;
		size_t size = 0;

		if (!strcmp(key, OVL_XATTR_OPAQUE)) {
			if (!S_ISDIR(inode->i_mode)) {
				erofs_dbg("file %s: opaque xattr on non-dir",
					  inode->i_srcpath);
				ret = -EINVAL;
				goto out;
			}
			inode->opaque = true;
		}

		ret = erofs_getxattr(inode, key, NULL, 0);
		if (ret < 0)
			goto out;
		if (ret) {
			size = ret;
			value = malloc(size);
			if (!value) {
				ret = -ENOMEM;
				goto out;
			}

			ret = erofs_getxattr(inode, key, value, size);
			if (ret < 0) {
				free(value);
				goto out;
			}
			DBG_BUGON(ret != size);
		} else if (S_ISDIR(inode->i_mode) &&
			   !strcmp(key, OVL_XATTR_ORIGIN)) {
			ret = 0;
			inode->whiteouts = true;
			continue;
		}

		ret = erofs_setxattr(inode, key, value, size);
		free(value);
		if (ret)
			break;
	}
out:
	free(keylst);
	return ret;
}

static inline unsigned int erofs_next_xattr_align(unsigned int pos,
						  struct erofs_xattritem *item)
{
	return EROFS_XATTR_ALIGN(pos + sizeof(struct erofs_xattr_entry) +
			item->len[0] + item->len[1] - item->prefix_len);
}

int erofs_prepare_xattr_ibody(struct erofs_inode *inode, bool noroom)
{
	unsigned int target_xattr_isize = inode->xattr_isize;
	struct list_head *ixattrs = &inode->i_xattrs;
	struct erofs_inode_xattr_node *node;
	unsigned int h_shared_count;
	int ret;

	if (list_empty(ixattrs)) {
		ret = 0;
		goto out;
	}

	/* get xattr ibody size */
	h_shared_count = 0;
	ret = sizeof(struct erofs_xattr_ibody_header);
	list_for_each_entry(node, ixattrs, list) {
		struct erofs_xattritem *item = node->item;

		if (item->shared_xattr_id >= 0 && h_shared_count < UCHAR_MAX) {
			++h_shared_count;
			ret += sizeof(__le32);
			continue;
		}
		ret = erofs_next_xattr_align(ret, item);
	}
out:
	while (ret < target_xattr_isize) {
		ret += sizeof(struct erofs_xattr_entry);
		if (ret < target_xattr_isize)
			ret = EROFS_XATTR_ALIGN(ret +
				min_t(int, target_xattr_isize - ret, UINT16_MAX));
	}
	if (noroom && target_xattr_isize && ret > target_xattr_isize) {
		erofs_err("no enough space to keep xattrs @ nid %llu",
			  inode->nid | 0ULL);
		return -ENOSPC;
	}
	inode->xattr_isize = ret;
	return ret;
}

static int erofs_count_all_xattrs_from_path(struct erofs_sb_info *sbi,
					    const char *path)
{
	int ret;
	DIR *_dir;
	struct stat st;

	_dir = opendir(path);
	if (!_dir) {
		erofs_err("failed to opendir at %s: %s",
			  path, erofs_strerror(-errno));
		return -errno;
	}

	ret = 0;
	while (1) {
		struct dirent *dp;
		char buf[PATH_MAX];

		/*
		 * set errno to 0 before calling readdir() in order to
		 * distinguish end of stream and from an error.
		 */
		errno = 0;
		dp = readdir(_dir);
		if (!dp)
			break;

		if (is_dot_dotdot(dp->d_name))
			continue;

		ret = snprintf(buf, PATH_MAX, "%s/%s", path, dp->d_name);

		if (ret < 0 || ret >= PATH_MAX) {
			/* ignore the too long path */
			ret = -ENOMEM;
			goto fail;
		}

		ret = lstat(buf, &st);
		if (ret) {
			ret = -errno;
			goto fail;
		}

		ret = read_xattrs_from_file(sbi, buf, st.st_mode, NULL);
		if (ret)
			goto fail;

		if (!S_ISDIR(st.st_mode))
			continue;

		ret = erofs_count_all_xattrs_from_path(sbi, buf);
		if (ret)
			goto fail;
	}

	if (errno)
		ret = -errno;

fail:
	closedir(_dir);
	return ret;
}

static void erofs_cleanxattrs(struct erofs_xattrmgr *xamgr, bool sharedxattrs)
{
	struct erofs_xattritem *item, *n;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(xamgr->hash); ++i) {
		list_for_each_entry_safe(item, n, xamgr->hash + i, node) {
			if (sharedxattrs && item->shared_xattr_id >= 0)
				continue;
			list_del(&item->node);
			free((void *)item->kvbuf);
			free(item);
		}
	}

	if (sharedxattrs)
		return;
	xamgr->sharedxattr_count = 0;
}

static int comp_shared_xattritem(const void *a, const void *b)
{
	const struct erofs_xattritem *ia, *ib;
	unsigned int la, lb;
	int ret;

	ia = *((const struct erofs_xattritem **)a);
	ib = *((const struct erofs_xattritem **)b);
	la = EROFS_XATTR_KVSIZE(ia->len);
	lb = EROFS_XATTR_KVSIZE(ib->len);

	ret = memcmp(ia->kvbuf, ib->kvbuf, min(la, lb));
	if (ret != 0)
		return ret;

	return la > lb;
}

int erofs_xattr_flush_name_prefixes(struct erofs_importer *im, bool plain)
{
	const struct erofs_importer_params *params = im->params;
	struct erofs_sb_info *sbi = im->sbi;
	bool may_fragments = params->fragments || erofs_sb_has_fragments(sbi);
	struct erofs_vfile *vf = &sbi->bdev;
	struct erofs_bufmgr *bmgr = sbi->bmgr;
	struct erofs_buffer_head *bh = NULL;
	struct erofs_vfile _vf;
	struct ea_type_node *tnode;
	s64 start, offset = 0;
	int err;

	if (!ea_prefix_count)
		return 0;

	if (!plain) {
		if (erofs_sb_has_metabox(sbi)) {
			bmgr = erofs_metabox_bmgr(sbi);
			vf = bmgr->vf;
		} else if (may_fragments) {
			erofs_sb_set_fragments(sbi);
			_vf = (struct erofs_vfile){ .fd = erofs_packedfile(sbi) };
			vf = &_vf;
			offset = lseek(vf->fd, 0, SEEK_CUR);
			if (offset < 0)
				return -errno;
			bmgr = NULL;
		} else {
			plain = true;
		}
	}
	if (plain)
		erofs_sb_set_plain_xattr_pfx(sbi);

	if (bmgr) {
		bh = erofs_balloc(bmgr, XATTR, 0, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		(void)erofs_mapbh(bmgr, bh->block);
		offset = erofs_btell(bh, false);
	}

	if ((offset >> 2) > UINT32_MAX)
		return -EOVERFLOW;
	start = offset;

	sbi->xattr_prefix_start = (u32)offset >> 2;
	sbi->xattr_prefix_count = ea_prefix_count;

	list_for_each_entry(tnode, &ea_name_prefixes, list) {
		union {
			struct {
				__le16 size;
				struct erofs_xattr_long_prefix prefix;
			} s;
			u8 data[EROFS_NAME_LEN + 2 +
				sizeof(struct erofs_xattr_long_prefix)];
		} u;
		int len, infix_len;

		u.s.prefix.base_index = tnode->base_index;
		infix_len = tnode->type.prefix_len - tnode->base_len;
		memcpy(u.s.prefix.infix, tnode->type.prefix + tnode->base_len,
		       infix_len);
		len = sizeof(struct erofs_xattr_long_prefix) + infix_len;
		u.s.size = cpu_to_le16(len);
		err = erofs_io_pwrite(vf, &u.s, offset, sizeof(__le16) + len);
		if (err != sizeof(__le16) + len) {
			if (err < 0)
				return err;
			return -EIO;
		}
		offset = round_up(offset + sizeof(__le16) + len, 4);
	}

	if (bh) {
		bh->op = &erofs_drop_directly_bhops;
		err = erofs_bh_balloon(bh, offset - start);
		if (err < 0)
			return err;
		bh->op = &erofs_drop_directly_bhops;
		erofs_bdrop(bh, false);
	} else {
		DBG_BUGON(bmgr);
		if (lseek(vf->fd, offset, SEEK_CUR) < 0)
			return -errno;
	}
	erofs_sb_set_xattr_prefixes(sbi);
	return 0;
}

static void erofs_write_xattr_entry(char *buf, struct erofs_xattritem *item)
{
	struct erofs_xattr_entry entry = {
		.e_name_index = item->prefix,
		.e_name_len = item->len[0] - item->prefix_len,
		.e_value_size = cpu_to_le16(item->len[1]),
	};

	memcpy(buf, &entry, sizeof(entry));
	buf += sizeof(struct erofs_xattr_entry);
	memcpy(buf, item->kvbuf + item->prefix_len,
	       item->len[0] - item->prefix_len);
	buf += item->len[0] - item->prefix_len;
	memcpy(buf, item->kvbuf + item->len[0] + 1, item->len[1]);

	erofs_dbg("writing xattr %d %s (%d %s)", item->base_index, item->kvbuf,
			item->prefix, item->kvbuf + item->prefix_len);
}

int erofs_build_shared_xattrs_from_path(struct erofs_sb_info *sbi, const char *path)
{
	struct erofs_xattrmgr *xamgr = sbi->xamgr;
	struct erofs_xattritem *item, *n, **sorted_n;
	unsigned int sharedxattr_count, p, i;
	struct erofs_buffer_head *bh;
	char *buf;
	int ret;
	erofs_off_t off;
	erofs_off_t shared_xattrs_size = 0;

	/* check if xattr or shared xattr is disabled */
	if (cfg.c_inline_xattr_tolerance < 0 ||
	    cfg.c_inline_xattr_tolerance == INT_MAX)
		return 0;

	if (xamgr->sharedxattr_count) {
		DBG_BUGON(1);
		return -EINVAL;
	}

	ret = erofs_count_all_xattrs_from_path(sbi, path);
	if (ret)
		return ret;
	sharedxattr_count = xamgr->sharedxattr_count;
	if (!sharedxattr_count)
		goto out;

	sorted_n = malloc((sharedxattr_count + 1) * sizeof(n));
	if (!sorted_n)
		return -ENOMEM;

	i = 0;
	while (xamgr->shared_xattrs) {
		item = xamgr->shared_xattrs;
		sorted_n[i++] = item;
		xamgr->shared_xattrs = item->next_shared_xattr;
		shared_xattrs_size = erofs_next_xattr_align(shared_xattrs_size,
							    item);
	}
	DBG_BUGON(i != sharedxattr_count);
	sorted_n[i] = NULL;
	qsort(sorted_n, sharedxattr_count, sizeof(n), comp_shared_xattritem);

	buf = calloc(1, shared_xattrs_size);
	if (!buf) {
		free(sorted_n);
		return -ENOMEM;
	}

	bh = erofs_balloc(sbi->bmgr, XATTR, shared_xattrs_size, 0);
	if (IS_ERR(bh)) {
		free(sorted_n);
		free(buf);
		return PTR_ERR(bh);
	}
	bh->op = &erofs_skip_write_bhops;

	erofs_mapbh(NULL, bh->block);
	off = erofs_btell(bh, false);

	sbi->xattr_blkaddr = off / erofs_blksiz(sbi);
	off %= erofs_blksiz(sbi);
	p = 0;
	for (i = 0; i < sharedxattr_count; i++) {
		item = sorted_n[i];
		erofs_write_xattr_entry(buf + p, item);
		item->next_shared_xattr = sorted_n[i + 1];
		item->shared_xattr_id = (off + p) / sizeof(__le32);
		p = erofs_next_xattr_align(p, item);
	}
	xamgr->shared_xattrs = sorted_n[0];
	free(sorted_n);
	bh->op = &erofs_drop_directly_bhops;
	ret = erofs_dev_write(sbi, buf, erofs_btell(bh, false), shared_xattrs_size);
	free(buf);
	erofs_bdrop(bh, false);
out:
	erofs_cleanxattrs(xamgr, true);
	return ret;
}

char *erofs_export_xattr_ibody(struct erofs_inode *inode)
{
	struct list_head *ixattrs = &inode->i_xattrs;
	unsigned int size = inode->xattr_isize;
	struct erofs_inode_xattr_node *node, *n;
	struct erofs_xattritem *item;
	struct erofs_xattr_ibody_header *header;
	LIST_HEAD(ilst);
	unsigned int p;
	char *buf = calloc(1, size);

	if (!buf)
		return ERR_PTR(-ENOMEM);

	header = (struct erofs_xattr_ibody_header *)buf;
	header->h_shared_count = 0;

	if (cfg.c_xattr_name_filter) {
		u32 name_filter = 0;
		int hashbit;
		unsigned int base_len;

		list_for_each_entry(node, ixattrs, list) {
			item = node->item;
			base_len = xattr_types[item->base_index].prefix_len;
			hashbit = xxh32(item->kvbuf + base_len,
					item->len[0] - base_len,
					EROFS_XATTR_FILTER_SEED + item->base_index) &
				  (EROFS_XATTR_FILTER_BITS - 1);
			name_filter |= (1UL << hashbit);
		}
		name_filter = EROFS_XATTR_FILTER_DEFAULT & ~name_filter;

		header->h_name_filter = cpu_to_le32(name_filter);
		if (header->h_name_filter)
			erofs_sb_set_xattr_filter(inode->sbi);
	}

	p = sizeof(struct erofs_xattr_ibody_header);
	list_for_each_entry_safe(node, n, ixattrs, list) {
		item = node->item;
		list_del(&node->list);

		/* move inline xattrs to the onstack list */
		if (item->shared_xattr_id < 0 ||
		    header->h_shared_count >= UCHAR_MAX) {
			list_add(&node->list, &ilst);
			continue;
		}

		*(__le32 *)(buf + p) = cpu_to_le32(item->shared_xattr_id);
		p += sizeof(__le32);
		++header->h_shared_count;
		free(node);
		put_xattritem(item);
	}

	list_for_each_entry_safe(node, n, &ilst, list) {
		item = node->item;
		erofs_write_xattr_entry(buf + p, item);
		p = erofs_next_xattr_align(p, item);
		list_del(&node->list);
		free(node);
		put_xattritem(item);
	}
	if (p < size) {
		memset(buf + p, 0, size - p);
	} else if (__erofs_unlikely(p > size)) {
		DBG_BUGON(1);
		free(buf);
		return ERR_PTR(-EFAULT);
	}
	return buf;
}

struct xattr_iter {
	struct erofs_sb_info *sbi;
	struct erofs_buf buf;
	void *kaddr;

	erofs_blk_t blkaddr;
	unsigned int ofs;
};

static int init_inode_xattrs(struct erofs_inode *vi)
{
	struct erofs_sb_info *sbi = vi->sbi;
	struct xattr_iter it;
	unsigned int i;
	struct erofs_xattr_ibody_header *ih;
	int ret = 0;

	/* the most case is that xattrs of this inode are initialized. */
	if (erofs_atomic_read(&vi->flags) & EROFS_I_EA_INITED)
		return ret;

	/*
	 * bypass all xattr operations if ->xattr_isize is not greater than
	 * sizeof(struct erofs_xattr_ibody_header), in detail:
	 * 1) it is not enough to contain erofs_xattr_ibody_header then
	 *    ->xattr_isize should be 0 (it means no xattr);
	 * 2) it is just to contain erofs_xattr_ibody_header, which is on-disk
	 *    undefined right now (maybe use later with some new sb feature).
	 */
	if (vi->xattr_isize == sizeof(struct erofs_xattr_ibody_header)) {
		erofs_err("xattr_isize %d of nid %llu is not supported yet",
			  vi->xattr_isize, vi->nid);
		return -EOPNOTSUPP;
	} else if (vi->xattr_isize < sizeof(struct erofs_xattr_ibody_header)) {
		if (vi->xattr_isize) {
			erofs_err("bogus xattr ibody @ nid %llu", vi->nid);
			DBG_BUGON(1);
			return -EFSCORRUPTED;	/* xattr ondisk layout error */
		}
		return -ENOATTR;
	}

	it.buf = __EROFS_BUF_INITIALIZER;
	it.blkaddr = erofs_blknr(sbi, erofs_iloc(vi) + vi->inode_isize);
	it.ofs = erofs_blkoff(sbi, erofs_iloc(vi) + vi->inode_isize);

	/* read in shared xattr array (non-atomic, see kmalloc below) */
	it.kaddr = erofs_read_metabuf(&it.buf, sbi, erofs_pos(sbi, it.blkaddr), false);
	if (IS_ERR(it.kaddr))
		return PTR_ERR(it.kaddr);

	ih = (struct erofs_xattr_ibody_header *)(it.kaddr + it.ofs);

	vi->xattr_shared_count = ih->h_shared_count;
	vi->xattr_shared_xattrs = malloc(vi->xattr_shared_count * sizeof(uint));
	if (!vi->xattr_shared_xattrs) {
		erofs_put_metabuf(&it.buf);
		return -ENOMEM;
	}

	/* let's skip ibody header */
	it.ofs += sizeof(struct erofs_xattr_ibody_header);

	for (i = 0; i < vi->xattr_shared_count; ++i) {
		if (it.ofs >= erofs_blksiz(sbi)) {
			/* cannot be unaligned */
			DBG_BUGON(it.ofs != erofs_blksiz(sbi));

			it.kaddr = erofs_read_metabuf(&it.buf, sbi,
					erofs_pos(sbi, ++it.blkaddr), false);
			if (IS_ERR(it.kaddr)) {
				free(vi->xattr_shared_xattrs);
				vi->xattr_shared_xattrs = NULL;
				return PTR_ERR(it.kaddr);
			}
			it.ofs = 0;
		}
		vi->xattr_shared_xattrs[i] =
			le32_to_cpu(*(__le32 *)(it.kaddr + it.ofs));
		it.ofs += sizeof(__le32);
	}
	erofs_put_metabuf(&it.buf);
	erofs_atomic_set_bit(EROFS_I_EA_INITED_BIT, &vi->flags);
	return ret;
}

/*
 * the general idea for these return values is
 * if    0 is returned, go on processing the current xattr;
 *       1 (> 0) is returned, skip this round to process the next xattr;
 *    -err (< 0) is returned, an error (maybe ENOXATTR) occurred
 *                            and need to be handled
 */
struct xattr_iter_handlers {
	int (*entry)(struct xattr_iter *_it, struct erofs_xattr_entry *entry);
	int (*name)(struct xattr_iter *_it, unsigned int processed, char *buf,
		    unsigned int len);
	int (*alloc_buffer)(struct xattr_iter *_it, unsigned int value_sz);
	void (*value)(struct xattr_iter *_it, unsigned int processed, char *buf,
		      unsigned int len);
};

static inline int xattr_iter_fixup(struct xattr_iter *it)
{
	struct erofs_sb_info *sbi = it->sbi;

	if (it->ofs < erofs_blksiz(sbi))
		return 0;

	it->blkaddr += erofs_blknr(sbi, it->ofs);
	it->kaddr = erofs_read_metabuf(&it->buf, sbi,
				       erofs_pos(sbi, it->blkaddr), false);
	if (IS_ERR(it->kaddr))
		return PTR_ERR(it->kaddr);
	it->ofs = erofs_blkoff(sbi, it->ofs);
	return 0;
}

static int inline_xattr_iter_begin(struct xattr_iter *it,
				   struct erofs_inode *vi)
{
	struct erofs_sb_info *sbi = vi->sbi;
	unsigned int xattr_header_sz, inline_xattr_ofs;

	xattr_header_sz = inlinexattr_header_size(vi);
	if (xattr_header_sz >= vi->xattr_isize) {
		DBG_BUGON(xattr_header_sz > vi->xattr_isize);
		return -ENOATTR;
	}

	inline_xattr_ofs = vi->inode_isize + xattr_header_sz;

	it->blkaddr = erofs_blknr(sbi, erofs_iloc(vi) + inline_xattr_ofs);
	it->ofs = erofs_blkoff(sbi, erofs_iloc(vi) + inline_xattr_ofs);

	it->kaddr = erofs_read_metabuf(&it->buf, sbi,
				       erofs_pos(sbi, it->blkaddr), false);
	if (IS_ERR(it->kaddr))
		return PTR_ERR(it->kaddr);
	return vi->xattr_isize - xattr_header_sz;
}

/*
 * Regardless of success or failure, `xattr_foreach' will end up with
 * `ofs' pointing to the next xattr item rather than an arbitrary position.
 */
static int xattr_foreach(struct xattr_iter *it,
			 const struct xattr_iter_handlers *op,
			 unsigned int *tlimit)
{
	struct erofs_sb_info *sbi = it->sbi;
	struct erofs_xattr_entry entry;
	unsigned int value_sz, processed, slice;
	int err;

	/* 0. fixup blkaddr, ofs, ipage */
	err = xattr_iter_fixup(it);
	if (err)
		return err;

	/*
	 * 1. read xattr entry to the memory,
	 *    since we do EROFS_XATTR_ALIGN
	 *    therefore entry should be in the page
	 */
	entry = *(struct erofs_xattr_entry *)(it->kaddr + it->ofs);
	if (tlimit) {
		unsigned int entry_sz = erofs_xattr_entry_size(&entry);

		/* xattr on-disk corruption: xattr entry beyond xattr_isize */
		if (*tlimit < entry_sz) {
			DBG_BUGON(1);
			return -EFSCORRUPTED;
		}
		*tlimit -= entry_sz;
	}

	it->ofs += sizeof(struct erofs_xattr_entry);
	value_sz = le16_to_cpu(entry.e_value_size);

	/* handle entry */
	err = op->entry(it, &entry);
	if (err) {
		it->ofs += entry.e_name_len + value_sz;
		goto out;
	}

	/* 2. handle xattr name (ofs will finally be at the end of name) */
	processed = 0;

	while (processed < entry.e_name_len) {
		if (it->ofs >= erofs_blksiz(sbi)) {
			DBG_BUGON(it->ofs > erofs_blksiz(sbi));

			err = xattr_iter_fixup(it);
			if (err)
				goto out;
			it->ofs = 0;
		}

		slice = min_t(unsigned int, erofs_blksiz(sbi) - it->ofs,
			      entry.e_name_len - processed);

		/* handle name */
		err = op->name(it, processed, it->kaddr + it->ofs, slice);
		if (err) {
			it->ofs += entry.e_name_len - processed + value_sz;
			goto out;
		}

		it->ofs += slice;
		processed += slice;
	}

	/* 3. handle xattr value */
	processed = 0;

	if (op->alloc_buffer) {
		err = op->alloc_buffer(it, value_sz);
		if (err) {
			it->ofs += value_sz;
			goto out;
		}
	}

	while (processed < value_sz) {
		if (it->ofs >= erofs_blksiz(sbi)) {
			DBG_BUGON(it->ofs > erofs_blksiz(sbi));

			err = xattr_iter_fixup(it);
			if (err)
				goto out;
			it->ofs = 0;
		}

		slice = min_t(unsigned int, erofs_blksiz(sbi) - it->ofs,
			      value_sz - processed);
		op->value(it, processed, it->kaddr + it->ofs, slice);
		it->ofs += slice;
		processed += slice;
	}

out:
	/* xattrs should be 4-byte aligned (on-disk constraint) */
	it->ofs = EROFS_XATTR_ALIGN(it->ofs);
	return err < 0 ? err : 0;
}

struct getxattr_iter {
	struct xattr_iter it;

	int buffer_size, index, infix_len;
	char *buffer;
	const char *name;
	size_t len;
};

static int erofs_xattr_long_entrymatch(struct getxattr_iter *it,
				       struct erofs_xattr_entry *entry)
{
	struct erofs_sb_info *sbi = it->it.sbi;
	struct erofs_xattr_prefix_item *pf = sbi->xattr_prefixes +
		(entry->e_name_index & EROFS_XATTR_LONG_PREFIX_MASK);

	if (pf >= sbi->xattr_prefixes + sbi->xattr_prefix_count)
		return -ENOATTR;

	if (it->index != pf->prefix->base_index ||
	    it->len != entry->e_name_len + pf->infix_len)
		return -ENOATTR;

	if (memcmp(it->name, pf->prefix->infix, pf->infix_len))
		return -ENOATTR;

	it->infix_len = pf->infix_len;
	return 0;
}

static int xattr_entrymatch(struct xattr_iter *_it,
			    struct erofs_xattr_entry *entry)
{
	struct getxattr_iter *it = container_of(_it, struct getxattr_iter, it);

	/* should also match the infix for long name prefixes */
	if (entry->e_name_index & EROFS_XATTR_LONG_PREFIX)
		return erofs_xattr_long_entrymatch(it, entry);

	if (it->index != entry->e_name_index ||
	    it->len != entry->e_name_len)
		return -ENOATTR;
	it->infix_len = 0;
	return 0;
}

static int xattr_namematch(struct xattr_iter *_it,
			   unsigned int processed, char *buf, unsigned int len)
{
	struct getxattr_iter *it = container_of(_it, struct getxattr_iter, it);

	if (memcmp(buf, it->name + it->infix_len + processed, len))
		return -ENOATTR;
	return 0;
}

static int xattr_checkbuffer(struct xattr_iter *_it,
			     unsigned int value_sz)
{
	struct getxattr_iter *it = container_of(_it, struct getxattr_iter, it);
	int err = it->buffer_size < value_sz ? -ERANGE : 0;

	it->buffer_size = value_sz;
	return !it->buffer ? 1 : err;
}

static void xattr_copyvalue(struct xattr_iter *_it,
			    unsigned int processed,
			    char *buf, unsigned int len)
{
	struct getxattr_iter *it = container_of(_it, struct getxattr_iter, it);

	memcpy(it->buffer + processed, buf, len);
}

static const struct xattr_iter_handlers find_xattr_handlers = {
	.entry = xattr_entrymatch,
	.name = xattr_namematch,
	.alloc_buffer = xattr_checkbuffer,
	.value = xattr_copyvalue
};

static int inline_getxattr(struct erofs_inode *vi, struct getxattr_iter *it)
{
	int ret;
	unsigned int remaining;

	ret = inline_xattr_iter_begin(&it->it, vi);
	if (ret < 0)
		return ret;

	remaining = ret;
	while (remaining) {
		ret = xattr_foreach(&it->it, &find_xattr_handlers, &remaining);
		if (ret != -ENOATTR)
			break;
	}

	return ret ? ret : it->buffer_size;
}

static int shared_getxattr(struct erofs_inode *vi, struct getxattr_iter *it)
{
	struct erofs_sb_info *sbi = vi->sbi;
	unsigned int i;
	int ret = -ENOATTR;

	for (i = 0; i < vi->xattr_shared_count; ++i) {
		erofs_blk_t blkaddr =
			xattrblock_addr(vi, vi->xattr_shared_xattrs[i]);

		it->it.ofs = xattrblock_offset(vi, vi->xattr_shared_xattrs[i]);
		it->it.kaddr = erofs_read_metabuf(&it->it.buf, sbi,
						  erofs_pos(sbi, blkaddr), false);
		if (IS_ERR(it->it.kaddr))
			return PTR_ERR(it->it.kaddr);
		it->it.blkaddr = blkaddr;

		ret = xattr_foreach(&it->it, &find_xattr_handlers, NULL);
		if (ret != -ENOATTR)
			break;
	}

	return ret ? ret : it->buffer_size;
}

int erofs_getxattr(struct erofs_inode *vi, const char *name, char *buffer,
		   size_t buffer_size)
{
	int ret;
	unsigned int prefix, prefixlen;
	struct getxattr_iter it;

	if (!name)
		return -EINVAL;

	ret = init_inode_xattrs(vi);
	if (ret)
		return ret;

	if (!erofs_xattr_prefix_matches(name, &prefix, &prefixlen))
		return -ENODATA;
	it.it.sbi = vi->sbi;
	it.index = prefix;
	it.name = name + prefixlen;
	it.len = strlen(it.name);
	if (it.len > EROFS_NAME_LEN)
		return -ERANGE;

	it.it.buf = __EROFS_BUF_INITIALIZER;
	it.buffer = buffer;
	it.buffer_size = buffer_size;

	ret = inline_getxattr(vi, &it);
	if (ret == -ENOATTR)
		ret = shared_getxattr(vi, &it);
	erofs_put_metabuf(&it.it.buf);
	return ret;
}

struct listxattr_iter {
	struct xattr_iter it;

	char *buffer;
	int buffer_size, buffer_ofs;
};

static int xattr_entrylist(struct xattr_iter *_it,
			   struct erofs_xattr_entry *entry)
{
	struct listxattr_iter *it =
		container_of(_it, struct listxattr_iter, it);
	unsigned int base_index = entry->e_name_index;
	unsigned int prefix_len, infix_len = 0;
	const char *prefix, *infix = NULL;

	if (entry->e_name_index & EROFS_XATTR_LONG_PREFIX) {
		struct erofs_sb_info *sbi = _it->sbi;
		struct erofs_xattr_prefix_item *pf = sbi->xattr_prefixes +
			(entry->e_name_index & EROFS_XATTR_LONG_PREFIX_MASK);

		if (pf >= sbi->xattr_prefixes + sbi->xattr_prefix_count)
			return 1;
		infix = pf->prefix->infix;
		infix_len = pf->infix_len;
		base_index = pf->prefix->base_index;
	}

	if (!base_index || base_index >= ARRAY_SIZE(xattr_types))
		return 1;
	prefix = xattr_types[base_index].prefix;
	prefix_len = xattr_types[base_index].prefix_len;

	if (!it->buffer) {
		it->buffer_ofs += prefix_len + infix_len +
					entry->e_name_len + 1;
		return 1;
	}

	if (it->buffer_ofs + prefix_len + infix_len
		+ entry->e_name_len + 1 > it->buffer_size)
		return -ERANGE;

	memcpy(it->buffer + it->buffer_ofs, prefix, prefix_len);
	memcpy(it->buffer + it->buffer_ofs + prefix_len, infix, infix_len);
	it->buffer_ofs += prefix_len + infix_len;
	return 0;
}

static int xattr_namelist(struct xattr_iter *_it,
			  unsigned int processed, char *buf, unsigned int len)
{
	struct listxattr_iter *it =
		container_of(_it, struct listxattr_iter, it);

	memcpy(it->buffer + it->buffer_ofs, buf, len);
	it->buffer_ofs += len;
	return 0;
}

static int xattr_skipvalue(struct xattr_iter *_it,
			   unsigned int value_sz)
{
	struct listxattr_iter *it =
		container_of(_it, struct listxattr_iter, it);

	it->buffer[it->buffer_ofs++] = '\0';
	return 1;
}

static const struct xattr_iter_handlers list_xattr_handlers = {
	.entry = xattr_entrylist,
	.name = xattr_namelist,
	.alloc_buffer = xattr_skipvalue,
	.value = NULL
};

static int inline_listxattr(struct erofs_inode *vi, struct listxattr_iter *it)
{
	int ret;
	unsigned int remaining;

	ret = inline_xattr_iter_begin(&it->it, vi);
	if (ret < 0)
		return ret;

	remaining = ret;
	while (remaining) {
		ret = xattr_foreach(&it->it, &list_xattr_handlers, &remaining);
		if (ret)
			break;
	}

	return ret ? ret : it->buffer_ofs;
}

static int shared_listxattr(struct erofs_inode *vi, struct listxattr_iter *it)
{
	struct erofs_sb_info *sbi = vi->sbi;
	unsigned int i;
	int ret = 0;

	for (i = 0; i < vi->xattr_shared_count; ++i) {
		erofs_blk_t blkaddr =
			xattrblock_addr(vi, vi->xattr_shared_xattrs[i]);

		it->it.ofs = xattrblock_offset(vi, vi->xattr_shared_xattrs[i]);
		it->it.kaddr = erofs_read_metabuf(&it->it.buf, sbi,
						  erofs_pos(sbi, blkaddr), false);
		if (IS_ERR(it->it.kaddr))
			return PTR_ERR(it->it.kaddr);
		it->it.blkaddr = blkaddr;

		ret = xattr_foreach(&it->it, &list_xattr_handlers, NULL);
		if (ret)
			break;
	}

	return ret ? ret : it->buffer_ofs;
}

int erofs_listxattr(struct erofs_inode *vi, char *buffer, size_t buffer_size)
{
	int ret;
	struct listxattr_iter it;

	ret = init_inode_xattrs(vi);
	if (ret == -ENOATTR)
		return 0;
	if (ret)
		return ret;

	it.it.sbi = vi->sbi;
	it.it.buf = __EROFS_BUF_INITIALIZER;
	it.buffer = buffer;
	it.buffer_size = buffer_size;
	it.buffer_ofs = 0;

	ret = inline_listxattr(vi, &it);
	if (ret < 0 && ret != -ENOATTR)
		ret = shared_listxattr(vi, &it);
	erofs_put_metabuf(&it.it.buf);
	return ret;
}

int erofs_xattr_insert_name_prefix(const char *prefix)
{
	struct ea_type_node *tnode;

	if (ea_prefix_count >= 0x80 || strlen(prefix) > UINT8_MAX)
		return -EOVERFLOW;

	tnode = calloc(1, sizeof(*tnode));
	if (!tnode)
		return -ENOMEM;

	if (!erofs_xattr_prefix_matches(prefix, &tnode->base_index,
					&tnode->base_len)) {
		free(tnode);
		return -ENODATA;
	}

	tnode->type.prefix_len = strlen(prefix);
	tnode->type.prefix = strdup(prefix);
	if (!tnode->type.prefix) {
		free(tnode);
		return -ENOMEM;
	}

	tnode->index = EROFS_XATTR_LONG_PREFIX | ea_prefix_count;
	ea_prefix_count++;
	init_list_head(&tnode->list);
	list_add_tail(&tnode->list, &ea_name_prefixes);
	return 0;
}

void erofs_xattr_cleanup_name_prefixes(void)
{
	struct ea_type_node *tnode, *n;

	list_for_each_entry_safe(tnode, n, &ea_name_prefixes, list) {
		list_del(&tnode->list);
		free((void *)tnode->type.prefix);
		free(tnode);
	}
}

void erofs_xattr_prefixes_cleanup(struct erofs_sb_info *sbi)
{
	int i;

	if (sbi->xattr_prefixes) {
		for (i = 0; i < sbi->xattr_prefix_count; i++)
			free(sbi->xattr_prefixes[i].prefix);
		free(sbi->xattr_prefixes);
		sbi->xattr_prefixes = NULL;
	}
}

int erofs_xattr_prefixes_init(struct erofs_sb_info *sbi)
{
	bool plain = erofs_sb_has_plain_xattr_pfx(sbi);
	erofs_off_t pos = (erofs_off_t)sbi->xattr_prefix_start << 2;
	struct erofs_xattr_prefix_item *pfs;
	erofs_nid_t nid = 0;
	int ret = 0, i, len;
	void *buf;

	if (!sbi->xattr_prefix_count)
		return 0;

	if (!plain) {
		if (sbi->metabox_nid)
			nid = sbi->metabox_nid;
		else if (sbi->packed_nid)
			nid = sbi->packed_nid;
	}

	pfs = calloc(sbi->xattr_prefix_count, sizeof(*pfs));
	if (!pfs)
		return -ENOMEM;

	for (i = 0; i < sbi->xattr_prefix_count; i++) {
		buf = erofs_read_metadata(sbi, nid, &pos, &len);
		if (IS_ERR(buf)) {
			ret = PTR_ERR(buf);
			goto out;
		}
		if (len < sizeof(*pfs->prefix) ||
		    len > EROFS_NAME_LEN + sizeof(*pfs->prefix)) {
			free(buf);
			ret = -EFSCORRUPTED;
			goto out;
		}
		pfs[i].prefix = buf;
		pfs[i].infix_len = len - sizeof(struct erofs_xattr_long_prefix);
	}
out:
	sbi->xattr_prefixes = pfs;
	if (ret)
		erofs_xattr_prefixes_cleanup(sbi);
	return ret;
}

void erofs_xattr_exit(struct erofs_sb_info *sbi)
{
	struct erofs_xattrmgr *xamgr = sbi->xamgr;

	erofs_xattr_prefixes_cleanup(sbi);
	if (!xamgr)
		return;
	erofs_cleanxattrs(xamgr, false);
	sbi->xamgr = NULL;
	free(xamgr);
}
