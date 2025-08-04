// SPDX-License-Identifier: GPL-2.0+
/*
 * Created by Li Guifu <blucerlee@gmail.com>
 * Lowlevel added by Li Yiyan <lyy0627@sjtu.edu.cn>
 */
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include "macosx.h"
#include "erofs/config.h"
#include "erofs/print.h"
#include "erofs/dir.h"
#include "erofs/inode.h"
#include "erofs/fragments.h"

#include <float.h>
#include <fuse.h>
#include <fuse_lowlevel.h>

#define EROFSFUSE_TIMEOUT DBL_MAX

struct erofsfuse_readdir_context {
	struct erofs_dir_context ctx;

	fuse_req_t req;
	void *buf;
	int is_plus;
	size_t index;
	size_t buf_rem;
	size_t offset;
	struct fuse_file_info *fi;
};

struct erofsfuse_lookupdir_context {
	struct erofs_dir_context ctx;

	const char *target_name;
	struct fuse_entry_param *ent;
};

static inline erofs_nid_t erofsfuse_to_nid(fuse_ino_t ino)
{
	if (ino == FUSE_ROOT_ID)
		return g_sbi.root_nid;
	return (erofs_nid_t)(ino - FUSE_ROOT_ID);
}

static inline fuse_ino_t erofsfuse_to_ino(erofs_nid_t nid)
{
	if (nid == g_sbi.root_nid)
		return FUSE_ROOT_ID;
	return (nid + FUSE_ROOT_ID);
}

static void erofsfuse_fill_stat(struct erofs_inode *vi, struct stat *stbuf)
{
	if (S_ISBLK(vi->i_mode) || S_ISCHR(vi->i_mode))
		stbuf->st_rdev = vi->u.i_rdev;

	stbuf->st_mode = vi->i_mode;
	stbuf->st_nlink = vi->i_nlink;
	stbuf->st_size = vi->i_size;
	stbuf->st_blocks = roundup(vi->i_size, erofs_blksiz(&g_sbi)) >> 9;
	stbuf->st_uid = vi->i_uid;
	stbuf->st_gid = vi->i_gid;
	stbuf->st_ctime = vi->i_mtime;
	stbuf->st_mtime = stbuf->st_ctime;
	stbuf->st_atime = stbuf->st_ctime;
}

static int erofsfuse_add_dentry(struct erofs_dir_context *ctx)
{
	size_t entsize = 0;
	char dname[EROFS_NAME_LEN + 1];
	struct erofsfuse_readdir_context *readdir_ctx = (void *)ctx;

	if (readdir_ctx->index < readdir_ctx->offset) {
		readdir_ctx->index++;
		return 0;
	}

	strncpy(dname, ctx->dname, ctx->de_namelen);
	dname[ctx->de_namelen] = '\0';

	if (!readdir_ctx->is_plus) { /* fuse 3 still use non-plus readdir */
		struct stat st = { 0 };

		st.st_mode = erofs_ftype_to_mode(ctx->de_ftype, 0);
		st.st_ino = erofsfuse_to_ino(ctx->de_nid);
		entsize = fuse_add_direntry(readdir_ctx->req, readdir_ctx->buf,
					 readdir_ctx->buf_rem, dname, &st,
					 readdir_ctx->index + 1);
	} else {
#if FUSE_MAJOR_VERSION >= 3
		int ret;
		struct erofs_inode vi = {
			.sbi = &g_sbi,
			.nid = ctx->de_nid
		};

		ret = erofs_read_inode_from_disk(&vi);
		if (ret < 0)
			return ret;

		struct fuse_entry_param param = {
			.ino = erofsfuse_to_ino(ctx->de_nid),
			.attr.st_ino = erofsfuse_to_ino(ctx->de_nid),
			.generation = 0,

			.attr_timeout = EROFSFUSE_TIMEOUT,
			.entry_timeout = EROFSFUSE_TIMEOUT,
		};
		erofsfuse_fill_stat(&vi, &(param.attr));

		entsize = fuse_add_direntry_plus(readdir_ctx->req,
					      readdir_ctx->buf,
					      readdir_ctx->buf_rem, dname,
					      &param, readdir_ctx->index + 1);
#else
		return -EOPNOTSUPP;
#endif
	}

	if (entsize > readdir_ctx->buf_rem)
		return 1;
	readdir_ctx->index++;
	readdir_ctx->buf += entsize;
	readdir_ctx->buf_rem -= entsize;
	return 0;
}

static int erofsfuse_lookup_dentry(struct erofs_dir_context *ctx)
{
	struct erofsfuse_lookupdir_context *lookup_ctx = (void *)ctx;

	if (lookup_ctx->ent->ino != 0 ||
	    strlen(lookup_ctx->target_name) != ctx->de_namelen)
		return 0;

	if (!strncmp(lookup_ctx->target_name, ctx->dname, ctx->de_namelen)) {
		int ret;
		struct erofs_inode vi = {
			.sbi = &g_sbi,
			.nid = (erofs_nid_t)ctx->de_nid,
		};

		ret = erofs_read_inode_from_disk(&vi);
		if (ret < 0)
			return ret;

		lookup_ctx->ent->ino = erofsfuse_to_ino(ctx->de_nid);
		lookup_ctx->ent->attr.st_ino = erofsfuse_to_ino(ctx->de_nid);

		erofsfuse_fill_stat(&vi, &(lookup_ctx->ent->attr));
	}
	return 0;
}

static inline void erofsfuse_readdir_general(fuse_req_t req, fuse_ino_t ino,
					     size_t size, off_t off,
					     struct fuse_file_info *fi,
					     int plus)
{
	int ret = 0;
	char *buf = NULL;
	struct erofsfuse_readdir_context ctx = { 0 };
	struct erofs_inode *vi = (struct erofs_inode *)fi->fh;

	erofs_dbg("readdir(%llu): size: %zu, off: %lu, plus: %d", ino | 0ULL,
		  size, off, plus);

	buf = malloc(size);
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}
	ctx.ctx.dir = vi;
	ctx.ctx.cb = erofsfuse_add_dentry;

	ctx.fi = fi;
	ctx.buf = buf;
	ctx.buf_rem = size;
	ctx.req = req;
	ctx.index = 0;
	ctx.offset = off;
	ctx.is_plus = plus;

#ifdef NDEBUG
	ret = erofs_iterate_dir(&ctx.ctx, false);
#else
	ret = erofs_iterate_dir(&ctx.ctx, true);
#endif

	if (ret < 0) /* if buffer insufficient, return 1 */
		fuse_reply_err(req, -ret);
	else
		fuse_reply_buf(req, buf, size - ctx.buf_rem);

	free(buf);
}

static void erofsfuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			      off_t off, struct fuse_file_info *fi)
{
	erofsfuse_readdir_general(req, ino, size, off, fi, 0);
}

#if FUSE_MAJOR_VERSION >= 3
static void erofsfuse_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
				  off_t off, struct fuse_file_info *fi)
{
	erofsfuse_readdir_general(req, ino, size, off, fi, 1);
}
#endif

static void erofsfuse_init(void *userdata, struct fuse_conn_info *conn)
{
	erofs_info("Using FUSE protocol %d.%d", conn->proto_major,
		   conn->proto_minor);
}

static void erofsfuse_open(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi)
{
	int ret = 0;
	struct erofs_inode *vi;

	if (fi->flags & (O_WRONLY | O_RDWR)) {
		fuse_reply_err(req, EROFS);
		return;
	}

	vi = calloc(1, sizeof(struct erofs_inode));
	if (!vi) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	vi->sbi = &g_sbi;
	vi->nid = erofsfuse_to_nid(ino);
	ret = erofs_read_inode_from_disk(vi);
	if (ret < 0) {
		fuse_reply_err(req, -ret);
		goto out;
	}

	if (!S_ISREG(vi->i_mode)) {
		fuse_reply_err(req, EISDIR);
	} else {
		fi->fh = (uint64_t)vi;
		fi->keep_cache = 1;
		fuse_reply_open(req, fi);
		return;
	}

out:
	free(vi);
}

static void erofsfuse_getattr(fuse_req_t req, fuse_ino_t ino,
			      struct fuse_file_info *fi)
{
	int ret;
	struct stat stbuf = { 0 };
	struct erofs_inode vi = { .sbi = &g_sbi, .nid = erofsfuse_to_nid(ino) };

	ret = erofs_read_inode_from_disk(&vi);
	if (ret < 0)
		fuse_reply_err(req, -ret);

	erofsfuse_fill_stat(&vi, &stbuf);
	stbuf.st_ino = ino;

	fuse_reply_attr(req, &stbuf, EROFSFUSE_TIMEOUT);
}

static void erofsfuse_opendir(fuse_req_t req, fuse_ino_t ino,
			      struct fuse_file_info *fi)
{
	int ret;
	struct erofs_inode *vi;

	vi = calloc(1, sizeof(struct erofs_inode));
	if (!vi) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	vi->sbi = &g_sbi;
	vi->nid = erofsfuse_to_nid(ino);
	ret = erofs_read_inode_from_disk(vi);
	if (ret < 0) {
		fuse_reply_err(req, -ret);
		goto out;
	}

	if (!S_ISDIR(vi->i_mode)) {
		fuse_reply_err(req, ENOTDIR);
		goto out;
	}

	fi->fh = (uint64_t)vi;
	fi->cache_readdir = 1;
	fi->keep_cache = 1;
	fuse_reply_open(req, fi);
	return;

out:
	free(vi);
}

static void erofsfuse_release(fuse_req_t req, fuse_ino_t ino,
			      struct fuse_file_info *fi)
{
	free((struct erofs_inode *)fi->fh);
	fi->fh = 0;
	fuse_reply_err(req, 0);
}

static void erofsfuse_lookup(fuse_req_t req, fuse_ino_t parent,
			     const char *name)
{
	int ret;
	struct erofs_inode *vi;
	struct fuse_entry_param fentry = { 0 };
	struct erofsfuse_lookupdir_context ctx = { 0 };

	vi = calloc(1, sizeof(struct erofs_inode));
	if (!vi) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	vi->sbi = &g_sbi;
	vi->nid = erofsfuse_to_nid(parent);
	ret = erofs_read_inode_from_disk(vi);
	if (ret < 0) {
		fuse_reply_err(req, -ret);
		goto out;
	}

	memset(&fentry, 0, sizeof(fentry));
	fentry.ino = 0;
	fentry.attr_timeout = fentry.entry_timeout = EROFSFUSE_TIMEOUT;
	ctx.ctx.dir = vi;
	ctx.ctx.cb = erofsfuse_lookup_dentry;

	ctx.ent = &fentry;
	ctx.target_name = name;

#ifdef NDEBUG
	ret = erofs_iterate_dir(&ctx.ctx, false);
#else
	ret = erofs_iterate_dir(&ctx.ctx, true);
#endif

	if (ret < 0) {
		fuse_reply_err(req, -ret);
		goto out;
	}
	fuse_reply_entry(req, &fentry);

out:
	free(vi);
}

static void erofsfuse_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			   off_t off, struct fuse_file_info *fi)
{
	struct erofs_inode *vi = (struct erofs_inode *)fi->fh;
	struct erofs_vfile vf;
	char *buf = NULL;
	int ret;

	erofs_dbg("read(%llu): size = %zu, off = %lu", ino | 0ULL, size, off);
	ret = erofs_iopen(&vf, vi);
	if (ret) {
		fuse_reply_err(req, -ret);
		return;
	}

	buf = malloc(size);
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	ret = erofs_pread(&vf, buf, size, off);
	if (ret) {
		fuse_reply_err(req, -ret);
		goto out;
	}
	if (off >= vi->i_size)
		ret = 0;
	else if (off + size > vi->i_size)
		ret = vi->i_size - off;
	else
		ret = size;

	fuse_reply_buf(req, buf, ret);

out:
	free(buf);
}

static void erofsfuse_readlink(fuse_req_t req, fuse_ino_t ino)
{
	struct erofs_inode vi = { .sbi = &g_sbi, .nid = erofsfuse_to_nid(ino) };
	struct erofs_vfile vf;
	char *buf = NULL;
	int ret;

	ret = erofs_read_inode_from_disk(&vi);
	if (ret < 0) {
		fuse_reply_err(req, -ret);
		return;
	}

	ret = erofs_iopen(&vf, &vi);
	if (ret) {
		fuse_reply_err(req, -ret);
		return;
	}

	buf = malloc(vi.i_size + 1);
	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	ret = erofs_pread(&vf, buf, vi.i_size, 0);
	if (ret < 0) {
		fuse_reply_err(req, -ret);
		goto out;
	}

	buf[vi.i_size] = '\0';
	fuse_reply_readlink(req, buf);

out:
	free(buf);
}

static void erofsfuse_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			       size_t size
#ifdef __APPLE__
			       , uint32_t position)
#else
			       )
#endif
{
	int ret;
	char *buf = NULL;
	struct erofs_inode vi = { .sbi = &g_sbi, .nid = erofsfuse_to_nid(ino) };

	erofs_dbg("getattr(%llu): name = %s, size = %zu", ino | 0ULL, name, size);

	ret = erofs_read_inode_from_disk(&vi);
	if (ret < 0) {
		fuse_reply_err(req, -ret);
		return;
	}

	if (size != 0) {
		buf = malloc(size);
		if (!buf) {
			fuse_reply_err(req, ENOMEM);
			return;
		}
	}

	ret = erofs_getxattr(&vi, name, buf, size);
	if (ret < 0)
		fuse_reply_err(req, -ret);
	else if (size == 0)
		fuse_reply_xattr(req, ret);
	else
		fuse_reply_buf(req, buf, ret);

	free(buf);
}

static void erofsfuse_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	int ret;
	char *buf = NULL;
	struct erofs_inode vi = { .sbi = &g_sbi, .nid = erofsfuse_to_nid(ino) };

	erofs_dbg("listxattr(%llu): size = %zu", ino | 0ULL, size);

	ret = erofs_read_inode_from_disk(&vi);
	if (ret < 0) {
		fuse_reply_err(req, -ret);
		return;
	}

	if (size != 0) {
		buf = malloc(size);
		if (!buf) {
			fuse_reply_err(req, ENOMEM);
			return;
		}
	}

	ret = erofs_listxattr(&vi, buf, size);
	if (ret < 0)
		fuse_reply_err(req, -ret);
	else if (size == 0)
		fuse_reply_xattr(req, ret);
	else
		fuse_reply_buf(req, buf, ret);

	free(buf);
}

static struct fuse_lowlevel_ops erofsfuse_lops = {
	.getxattr = erofsfuse_getxattr,
	.opendir = erofsfuse_opendir,
	.releasedir = erofsfuse_release,
	.release = erofsfuse_release,
	.lookup = erofsfuse_lookup,
	.listxattr = erofsfuse_listxattr,
	.readlink = erofsfuse_readlink,
	.getattr = erofsfuse_getattr,
	.readdir = erofsfuse_readdir,
#if FUSE_MAJOR_VERSION >= 3
	.readdirplus = erofsfuse_readdirplus,
#endif
	.open = erofsfuse_open,
	.read = erofsfuse_read,
	.init = erofsfuse_init,
};

static struct options {
	const char *disk;
	const char *mountpoint;
	u64 offset;
	unsigned int debug_lvl;
	bool show_help;
	bool show_version;
	bool odebug;
} fusecfg;

#define OPTION(t, p) { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("--offset=%lu", offset),
	OPTION("--dbglevel=%u", debug_lvl),
	OPTION("--help", show_help),
	OPTION("--version", show_version),
	FUSE_OPT_KEY("--device=", 1),
	FUSE_OPT_END
};

static void usage(void)
{
#if FUSE_MAJOR_VERSION < 3
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

#else
	fuse_lowlevel_version();
#endif
	fputs("usage: [options] IMAGE MOUNTPOINT\n\n"
	      "Options:\n"
	      "    --offset=#             skip # bytes at the beginning of IMAGE\n"
	      "    --dbglevel=#           set output message level to # (maximum 9)\n"
	      "    --device=#             specify an extra device to be used together\n"
#if FUSE_MAJOR_VERSION < 3
	      "    --help                 display this help and exit\n"
	      "    --version              display erofsfuse version\n"
#endif
	      "\n", stderr);

#if FUSE_MAJOR_VERSION >= 3
	fputs("\nFUSE options:\n", stderr);
	fuse_cmdline_help();
#else
	fuse_opt_add_arg(&args, ""); /* progname */
	fuse_opt_add_arg(&args, "-ho"); /* progname */
	fuse_parse_cmdline(&args, NULL, NULL, NULL);
#endif
	exit(EXIT_FAILURE);
}

static int optional_opt_func(void *data, const char *arg, int key,
			     struct fuse_args *outargs)
{
	int ret;

	switch (key) {
	case 1:
		ret = erofs_blob_open_ro(&g_sbi, arg + sizeof("--device=") - 1);
		if (ret)
			return -1;
		++g_sbi.extra_devices;
		return 0;
	case FUSE_OPT_KEY_NONOPT:
		if (fusecfg.mountpoint)
			return -1; /* Too many args */

		if (!fusecfg.disk) {
			fusecfg.disk = strdup(arg);
			return 0;
		}
		if (!fusecfg.mountpoint)
			fusecfg.mountpoint = strdup(arg);
	case FUSE_OPT_KEY_OPT:
		if (!strcmp(arg, "-d"))
			fusecfg.odebug = true;
		if (!strcmp(arg, "-h"))
			fusecfg.show_help = true;
		if (!strcmp(arg, "-V"))
			fusecfg.show_version = true;
	}
	return 1; // keep arg
}

#if defined(HAVE_EXECINFO_H) && defined(HAVE_BACKTRACE)
#include <execinfo.h>

static void signal_handle_sigsegv(int signal)
{
	void *array[10];
	size_t nptrs;
	char **strings;
	size_t i;

	erofs_dump("========================================\n");
	erofs_dump("Segmentation Fault.  Starting backtrace:\n");
	nptrs = backtrace(array, 10);
	strings = backtrace_symbols(array, nptrs);
	if (strings) {
		for (i = 0; i < nptrs; i++)
			erofs_dump("%s\n", strings[i]);
		free(strings);
	}
	erofs_dump("========================================\n");
	abort();
}
#endif

#define EROFSFUSE_MOUNT_MSG	\
	erofs_warn("%s mounted on %s with offset %u",	\
		   fusecfg.disk, fusecfg.mountpoint, fusecfg.offset);

int main(int argc, char *argv[])
{
	int ret;
	struct fuse_session *se;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
#if FUSE_MAJOR_VERSION >= 3
	struct fuse_cmdline_opts opts = {};
#else
	struct fuse_chan *ch;
	struct {
		char *mountpoint;
		int mt, foreground;
	} opts = {};
#endif

	erofs_init_configure();
	fusecfg.debug_lvl = cfg.c_dbg_lvl;
	printf("erofsfuse %s\n", cfg.c_version);

#if defined(HAVE_EXECINFO_H) && defined(HAVE_BACKTRACE)
	if (signal(SIGSEGV, signal_handle_sigsegv) == SIG_ERR) {
		fprintf(stderr, "failed to initialize signals\n");
		ret = -errno;
		goto err;
	}
#endif

	/* parse options */
	ret = fuse_opt_parse(&args, &fusecfg, option_spec, optional_opt_func);
	if (ret)
		goto err;

#if FUSE_MAJOR_VERSION >= 3
	ret = fuse_parse_cmdline(&args, &opts);
#else
	ret = (fuse_parse_cmdline(&args, &opts.mountpoint, &opts.mt,
				  &opts.foreground) < 0);
#endif
	if (ret)
		goto err_fuse_free_args;

	if (fusecfg.show_help || fusecfg.show_version || !opts.mountpoint)
		usage();
	cfg.c_dbg_lvl = fusecfg.debug_lvl;

	if (fusecfg.odebug && cfg.c_dbg_lvl < EROFS_DBG)
		cfg.c_dbg_lvl = EROFS_DBG;

	g_sbi.bdev.offset = fusecfg.offset;
	ret = erofs_dev_open(&g_sbi, fusecfg.disk, O_RDONLY);
	if (ret) {
		fprintf(stderr, "failed to open: %s\n", fusecfg.disk);
		goto err_fuse_free_args;
	}

	ret = erofs_read_superblock(&g_sbi);
	if (ret) {
		fprintf(stderr, "failed to read erofs super block\n");
		goto err_dev_close;
	}

	if (erofs_sb_has_fragments(&g_sbi) && g_sbi.packed_nid > 0) {
		ret = erofs_packedfile_init(&g_sbi, false);
		if (ret) {
			erofs_err("failed to initialize packedfile: %s",
				  erofs_strerror(ret));
			goto err_super_put;
		}
	}

#if FUSE_MAJOR_VERSION >= 3
	se = fuse_session_new(&args, &erofsfuse_lops, sizeof(erofsfuse_lops),
			      NULL);
	if (!se)
		goto err_packedinode;

	if (fuse_session_mount(se, opts.mountpoint) >= 0) {
		EROFSFUSE_MOUNT_MSG
		if (fuse_daemonize(opts.foreground) >= 0) {
			if (fuse_set_signal_handlers(se) >= 0) {
				if (opts.singlethread) {
					ret = fuse_session_loop(se);
				} else {
#if FUSE_USE_VERSION == 30
					ret = fuse_session_loop_mt(se, opts.clone_fd);
#elif FUSE_USE_VERSION == 32
					struct fuse_loop_config config = {
						.clone_fd = opts.clone_fd,
						.max_idle_threads = opts.max_idle_threads
					};
					ret = fuse_session_loop_mt(se, &config);
#else
#error "FUSE_USE_VERSION not supported"
#endif
				}
				fuse_remove_signal_handlers(se);
			}
			fuse_session_unmount(se);
			fuse_session_destroy(se);
		}
	}
#else
	ch = fuse_mount(opts.mountpoint, &args);
	if (!ch)
		goto err_packedinode;
	EROFSFUSE_MOUNT_MSG
	se = fuse_lowlevel_new(&args, &erofsfuse_lops, sizeof(erofsfuse_lops),
			       NULL);
	if (se) {
		if (fuse_daemonize(opts.foreground) != -1) {
			if (fuse_set_signal_handlers(se) != -1) {
				fuse_session_add_chan(se, ch);
				if (opts.mt)
					ret = fuse_session_loop_mt(se);
				else
					ret = fuse_session_loop(se);
				fuse_remove_signal_handlers(se);
				fuse_session_remove_chan(ch);
			}
		}
		fuse_session_destroy(se);
	}
	fuse_unmount(opts.mountpoint, ch);
#endif

err_packedinode:
	erofs_packedfile_exit(&g_sbi);
err_super_put:
	erofs_put_super(&g_sbi);
err_dev_close:
	erofs_blob_closeall(&g_sbi);
	erofs_dev_close(&g_sbi);
err_fuse_free_args:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);
err:
	erofs_exit_configure();
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
