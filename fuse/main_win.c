// SPDX-License-Identifier: GPL-2.0+
/*
 * Created by Li Guifu <blucerlee@gmail.com>
 */
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <fuse.h>
#include <fuse_opt.h>
#include "macosx.h"
#include "erofs/config.h"
#include "erofs/print.h"
#include "erofs/io.h"
#include "erofs/dir.h"
#include "erofs/inode.h"

struct erofsfuse_dir_context {
	struct erofs_dir_context ctx;
	fuse_fill_dir_t filler;
	struct fuse_file_info *fi;
	void *buf;
};

static int erofsfuse_fill_dentries(struct erofs_dir_context *ctx)
{
	struct erofsfuse_dir_context *fusectx = (void *)ctx;
	struct stat st = {0};
	char dname[EROFS_NAME_LEN + 1];

	strncpy(dname, ctx->dname, ctx->de_namelen);
	dname[ctx->de_namelen] = '\0';
	st.st_mode = erofs_ftype_to_dtype(ctx->de_ftype) << 12;
#if FUSE_MAJOR_VERSION >= 3
	fusectx->filler(fusectx->buf, dname, &st, 0, FUSE_FILL_DIR_PLUS);
#else
	fusectx->filler(fusectx->buf, dname, &st, 0);
#endif
	return 0;
}

int erofsfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
					  off_t offset, struct fuse_file_info *fi)
{
	int ret;
	struct erofs_inode dir;
	struct erofsfuse_dir_context ctx = {
			.ctx.dir = &dir,
			.ctx.cb = erofsfuse_fill_dentries,
			.filler = filler,
			.fi = fi,
			.buf = buf,
	};
	erofs_dbg("readdir:%s offset=%llu", path, (long long)offset);

	dir.sbi = &sbi;
	ret = erofs_ilookup(path, &dir);
	if (ret)
		return ret;

	erofs_dbg("path=%s nid = %llu", path, dir.nid | 0ULL);
	if (!S_ISDIR(dir.i_mode))
		return -ENOTDIR;

	if (!dir.i_size)
		return 0;
#ifdef NDEBUG
	return erofs_iterate_dir(&ctx.ctx, false);
#else
	return erofs_iterate_dir(&ctx.ctx, true);
#endif
}

static void *erofsfuse_init(struct fuse_conn_info *info)
{
	erofs_info("Using FUSE protocol %d.%d", info->proto_major, info->proto_minor);
	return NULL;
}

static int erofsfuse_open(const char *path, struct fuse_file_info *fi)
{
	erofs_dbg("open path=%s", path);

	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int erofsfuse_getattr(const char *path, struct stat *stbuf)
{
	struct erofs_inode vi = { .sbi = &sbi };
	int ret;

	erofs_dbg("getattr(%s)", path);
	ret = erofs_ilookup(path, &vi);
	if (ret)
		return -ENOENT;

	stbuf->st_mode  = vi.i_mode;
	stbuf->st_nlink = vi.i_nlink;
	stbuf->st_size  = vi.i_size;
	stbuf->st_blocks = roundup(vi.i_size, erofs_blksiz(vi.sbi)) >> 9;
	stbuf->st_uid = vi.i_uid;
	stbuf->st_gid = vi.i_gid;
	if (S_ISBLK(vi.i_mode) || S_ISCHR(vi.i_mode))
		stbuf->st_rdev = vi.u.i_rdev;
	stbuf->st_ctime = vi.i_mtime;
	stbuf->st_mtime = stbuf->st_ctime;
	stbuf->st_atime = stbuf->st_ctime;
	return 0;
}

static int erofsfuse_read(const char *path, char *buffer,
						  size_t size, off_t offset,
						  struct fuse_file_info *fi)
{
	int ret;
	struct erofs_inode vi;

	erofs_dbg("path:%s size=%zd offset=%llu", path, size, (long long)offset);

	vi.sbi = &sbi;
	ret = erofs_ilookup(path, &vi);
	if (ret)
		return ret;

	ret = erofs_pread(&vi, buffer, size, offset);
	if (ret)
		return ret;
	if (offset >= vi.i_size)
		return 0;
	if (offset + size > vi.i_size)
		return vi.i_size - offset;
	return size;
}

static int erofsfuse_readlink(const char *path, char *buffer, size_t size)
{
	int ret = erofsfuse_read(path, buffer, size, 0, NULL);

	if (ret < 0)
		return ret;
	DBG_BUGON(ret > size);
	if (ret == size)
		buffer[size - 1] = '\0';
	erofs_dbg("readlink(%s): %s", path, buffer);
	return 0;
}

static int erofsfuse_getxattr(const char *path, const char *name, char *value,
							  size_t size
#ifdef __APPLE__
		, uint32_t position)
#else
)
#endif
{
	int ret;
	struct erofs_inode vi;

	erofs_dbg("getxattr(%s): name=%s size=%llu", path, name, size);

	vi.sbi = &sbi;
	ret = erofs_ilookup(path, &vi);
	if (ret)
		return ret;

	return erofs_getxattr(&vi, name, value, size);
}

static int erofsfuse_listxattr(const char *path, char *list, size_t size)
{
	int ret;
	struct erofs_inode vi;

	erofs_dbg("listxattr(%s): size=%llu", path, size);

	vi.sbi = &sbi;
	ret = erofs_ilookup(path, &vi);
	if (ret)
		return ret;

	return erofs_listxattr(&vi, list, size);
}

static struct fuse_operations erofs_ops = {
		.getxattr = erofsfuse_getxattr,
		.listxattr = erofsfuse_listxattr,
		.readlink = erofsfuse_readlink,
		.getattr = erofsfuse_getattr,
		.readdir = erofsfuse_readdir,
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
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

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

static void erofsfuse_dumpcfg(void)
{
	erofs_dump("disk: %s\n", fusecfg.disk);
	erofs_dump("offset: %llu\n", fusecfg.offset | 0ULL);
	erofs_dump("mountpoint: %s\n", fusecfg.mountpoint);
	erofs_dump("dbglevel: %u\n", cfg.c_dbg_lvl);
}

static int optional_opt_func(void *data, const char *arg, int key,
							 struct fuse_args *outargs)
{
	int ret;

	switch (key) {
		case 1:
			ret = blob_open_ro(&sbi, arg + sizeof("--device=") - 1);
			if (ret)
				return -1;
			++sbi.extra_devices;
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
	return 1;
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

int main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	erofs_init_configure();
	printf("%s %s\n", basename(argv[0]), cfg.c_version);

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

	if (fusecfg.show_help || fusecfg.show_version || !fusecfg.mountpoint)
		usage();
	cfg.c_dbg_lvl = fusecfg.debug_lvl;

	if (fusecfg.odebug && cfg.c_dbg_lvl < EROFS_DBG)
		cfg.c_dbg_lvl = EROFS_DBG;

	sbi.diskoffset = fusecfg.offset;

	erofsfuse_dumpcfg();
	ret = dev_open_ro(&sbi, fusecfg.disk);
	if (ret) {
		fprintf(stderr, "failed to open: %s\n", fusecfg.disk);
		goto err_fuse_free_args;
	}

	ret = erofs_read_superblock(&sbi);
	if (ret) {
		fprintf(stderr, "failed to read erofs super block\n");
		goto err_dev_close;
	}

	ret = fuse_main(args.argc, args.argv, &erofs_ops, NULL);

	erofs_put_super(&sbi);
err_dev_close:
	blob_closeall(&sbi);
	dev_close(&sbi);
err_fuse_free_args:
	fuse_opt_free_args(&args);
err:
	erofs_exit_configure();
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
