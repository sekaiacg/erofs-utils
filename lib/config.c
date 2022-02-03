// SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include "erofs/print.h"
#include "erofs/internal.h"
#include "liberofs_private.h"
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

struct erofs_configure cfg;
struct erofs_sb_info sbi;
bool erofs_stdout_tty;

void erofs_init_configure(void)
{
	memset(&cfg, 0, sizeof(cfg));

	cfg.c_dbg_lvl  = EROFS_WARN;
	cfg.c_version  = "1.4";
	cfg.c_dry_run  = false;
	cfg.c_ignore_mtime = false;
	cfg.c_force_inodeversion = 0;
	cfg.c_inline_xattr_tolerance = 2;
	cfg.c_unix_timestamp = -1;
	cfg.c_uid = -1;
	cfg.c_gid = -1;
	cfg.c_max_decompressed_extent_bytes = -1;
	erofs_stdout_tty = isatty(STDOUT_FILENO);
}

void erofs_show_config(void)
{
	const struct erofs_configure *c = &cfg;

	if (c->c_dbg_lvl < EROFS_INFO)
		return;
	erofs_dump("\tc_version:           [%8s]\n", c->c_version);
	erofs_dump("\tc_dbg_lvl:           [%8d]\n", c->c_dbg_lvl);
	erofs_dump("\tc_dry_run:           [%8d]\n", c->c_dry_run);
}

void erofs_exit_configure(void)
{
	int i;

#ifdef HAVE_LIBSELINUX
	if (cfg.sehnd)
		selabel_close(cfg.sehnd);
#endif
	if (cfg.c_img_path)
		free(cfg.c_img_path);
	if (cfg.c_src_path)
		free(cfg.c_src_path);
	for (i = 0; i < EROFS_MAX_COMPR_CFGS && cfg.c_compr_opts[i].alg; i++)
		free(cfg.c_compr_opts[i].alg);
}

static unsigned int fullpath_prefix;	/* root directory prefix length */

void erofs_set_fs_root(const char *rootdir)
{
	fullpath_prefix = strlen(rootdir);
}

const char *erofs_fspath(const char *fullpath)
{
	const char *s = fullpath + fullpath_prefix;

	while (*s == '/')
		s++;
	return s;
}

#ifdef HAVE_LIBSELINUX
int erofs_selabel_open(const char *file_contexts)
{
	struct selinux_opt seopts[] = {
		{ .type = SELABEL_OPT_PATH, .value = file_contexts }
	};

	if (cfg.sehnd) {
		erofs_info("ignore duplicated file contexts \"%s\"",
			   file_contexts);
		return -EBUSY;
	}

	cfg.sehnd = selabel_open(SELABEL_CTX_FILE, seopts, 1);
	if (!cfg.sehnd) {
		erofs_err("failed to open file contexts \"%s\"",
			  file_contexts);
		return -EINVAL;
	}
	return 0;
}
#endif

static bool __erofs_is_progressmsg;

char *erofs_trim_for_progressinfo(const char *str, int placeholder)
{
	int col, len;

	if (!erofs_stdout_tty) {
		return strdup(str);
	} else {
#ifdef GWINSZ_IN_SYS_IOCTL
		struct winsize winsize;

		if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) >= 0 &&
		   winsize.ws_col > 0)
			col = winsize.ws_col;
		else
#endif
			col = 80;
	}

	if (col <= placeholder)
		return strdup("");

	len = strlen(str);
	/* omit over long prefixes */
	if (len > col - placeholder) {
		char *s = strdup(str + len - (col - placeholder));

		if (col > placeholder + 2) {
			s[0] = '[';
			s[1] = ']';
		}
		return s;
	}
	return strdup(str);
}

void erofs_msg(int dbglv, const char *fmt, ...)
{
	va_list ap;
	FILE *f = dbglv >= EROFS_ERR ? stderr : stdout;

	if (__erofs_is_progressmsg) {
		fputc('\n', stdout);
		__erofs_is_progressmsg = false;
	}
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
}

void erofs_update_progressinfo(const char *fmt, ...)
{
	char msg[8192];
	va_list ap;

	if (cfg.c_dbg_lvl >= EROFS_INFO || !cfg.c_showprogress)
		return;

	va_start(ap, fmt);
	vsprintf(msg, fmt, ap);
	va_end(ap);

	if (erofs_stdout_tty) {
		printf("\r\033[K%s", msg);
		__erofs_is_progressmsg = true;
		fflush(stdout);
		return;
	}
	fputs(msg, stdout);
	fputc('\n', stdout);
}

unsigned int erofs_get_available_processors(void)
{
#if defined(HAVE_UNISTD_H) && defined(HAVE_SYSCONF)
	return sysconf(_SC_NPROCESSORS_ONLN);
#else
	return 0;
#endif
}
