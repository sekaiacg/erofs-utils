// SPDX-License-Identifier: GPL-2.0+
#define _GNU_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include "erofs/config.h"
#include "erofs/print.h"
#include "erofs/err.h"
#include "erofs/io.h"
#include "../lib/liberofs_nbd.h"
#ifdef HAVE_LINUX_LOOP_H
#include <linux/loop.h>
#else
#define LOOP_CTL_GET_FREE	0x4C82
#define LOOP_SET_FD		0x4C00
#define LOOP_SET_STATUS		0x4C02
enum {
	LO_FLAGS_AUTOCLEAR = 4,
};
struct loop_info {
	char	pad[44];
	int	lo_flags;
	char    pad1[120];
};
#endif
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

enum erofs_backend_drv {
	EROFSAUTO,
	EROFSLOCAL,
	EROFSFUSE,
	EROFSNBD,
};

enum erofsmount_mode {
	EROFSMOUNT_MODE_MOUNT,
	EROFSMOUNT_MODE_UMOUNT,
	EROFSMOUNT_MODE_REATTACH,
};

static struct erofsmount_cfg {
	char *device;
	char *target;
	char *options;
	char *full_options;		/* used for erofsfuse */
	char *fstype;
	long flags;
	enum erofs_backend_drv backend;
	enum erofsmount_mode mountmode;
} mountcfg = {
	.full_options = "ro",
	.flags = MS_RDONLY,		/* default mountflags */
	.fstype = "erofs",
};

static long erofsmount_parse_flagopts(char *s, long flags, char **more)
{
	static const struct {
		char *name;
		long flags;
	} opts[] = {
		{"defaults", 0}, {"quiet", 0}, // NOPs
		{"user", 0}, {"nouser", 0}, // checked in fstab, ignored in -o
		{"ro", MS_RDONLY}, {"rw", ~MS_RDONLY},
		{"nosuid", MS_NOSUID}, {"suid", ~MS_NOSUID},
		{"nodev", MS_NODEV}, {"dev", ~MS_NODEV},
		{"noexec", MS_NOEXEC}, {"exec", ~MS_NOEXEC},
		{"sync", MS_SYNCHRONOUS}, {"async", ~MS_SYNCHRONOUS},
		{"noatime", MS_NOATIME}, {"atime", ~MS_NOATIME},
		{"norelatime", ~MS_RELATIME}, {"relatime", MS_RELATIME},
		{"nodiratime", MS_NODIRATIME}, {"diratime", ~MS_NODIRATIME},
		{"loud", ~MS_SILENT},
		{"remount", MS_REMOUNT}, {"move", MS_MOVE},
		// mand dirsync rec iversion strictatime
	};

	for (;;) {
		char *comma;
		int i;

		comma = strchr(s, ',');
		if (comma)
			*comma = '\0';
		for (i = 0; i < ARRAY_SIZE(opts); ++i) {
			if (!strcasecmp(s, opts[i].name)) {
				if (opts[i].flags < 0)
					flags &= opts[i].flags;
				else
					flags |= opts[i].flags;
				break;
			}
		}

		if (more && i >= ARRAY_SIZE(opts)) {
			int sl = strlen(s);
			char *new = *more;

			i = new ? strlen(new) : 0;
			new = realloc(new, i + strlen(s) + 2);
			if (!new)
				return -ENOMEM;
			if (i)
				new[i++] = ',';
			memcpy(new + i, s, sl);
			new[i + sl] = '\0';
			*more = new;
		}

		if (!comma)
			break;
		*comma = ',';
		s = comma + 1;
	}
	return flags;
}

static int erofsmount_parse_options(int argc, char **argv)
{
	static const struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"reattach", no_argument, 0, 512},
		{0, 0, 0, 0},
	};
	char *dot;
	int opt;

	while ((opt = getopt_long(argc, argv, "Nfno:st:uv",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'o':
			mountcfg.full_options = optarg;
			mountcfg.flags =
				erofsmount_parse_flagopts(optarg, mountcfg.flags,
							  &mountcfg.options);
			break;
		case 't':
			dot = strchr(optarg, '.');
			if (dot) {
				if (!strcmp(dot + 1, "fuse")) {
					mountcfg.backend = EROFSFUSE;
				} else if (!strcmp(dot + 1, "local")) {
					mountcfg.backend = EROFSLOCAL;
				} else if (!strcmp(dot + 1, "nbd")) {
					mountcfg.backend = EROFSNBD;
				} else {
					erofs_err("invalid filesystem subtype `%s`", dot + 1);
					return -EINVAL;
				}
				*dot = '\0';
			}
			mountcfg.fstype = optarg;
			break;
		case 'u':
			mountcfg.mountmode = EROFSMOUNT_MODE_UMOUNT;
			break;
		case 512:
			mountcfg.mountmode = EROFSMOUNT_MODE_REATTACH;
			break;
		default:
			return -EINVAL;
		}
	}
	if (mountcfg.mountmode == EROFSMOUNT_MODE_MOUNT) {
		if (optind >= argc) {
			erofs_err("missing argument: DEVICE");
			return -EINVAL;
		}

		mountcfg.device = strdup(argv[optind++]);
		if (!mountcfg.device)
			return -ENOMEM;
	}
	if (optind >= argc) {
		if (mountcfg.mountmode == EROFSMOUNT_MODE_MOUNT)
			erofs_err("missing argument: MOUNTPOINT");
		else
			erofs_err("missing argument: TARGET");
		return -EINVAL;
	}

	mountcfg.target = strdup(argv[optind++]);
	if (!mountcfg.target)
		return -ENOMEM;

	if (optind < argc) {
		erofs_err("unexpected argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	return 0;
}

static int erofsmount_fuse(const char *source, const char *mountpoint,
			   const char *fstype, const char *options)
{
	char *command;
	int err;

	if (strcmp(fstype, "erofs")) {
		fprintf(stderr, "unsupported filesystem type `%s`\n",
			mountcfg.fstype);
		return -ENODEV;
	}

	err = asprintf(&command, "erofsfuse -o%s %s %s", options,
		       source, mountpoint);
	if (err < 0)
		return -ENOMEM;

	/* execvp() doesn't work for external mount helpers here */
	err = execl("/bin/sh", "/bin/sh", "-c", command, NULL);
	if (err < 0) {
		perror("failed to execute /bin/sh");
		return -errno;
	}
	return 0;
}

struct erofsmount_nbd_ctx {
	struct erofs_vfile vd;		/* virtual device */
	struct erofs_vfile sk;		/* socket file */
};

static void *erofsmount_nbd_loopfn(void *arg)
{
	struct erofsmount_nbd_ctx *ctx = arg;
	int err;

	while (1) {
		struct erofs_nbd_request rq;
		ssize_t rem;
		off_t pos;

		err = erofs_nbd_get_request(ctx->sk.fd, &rq);
		if (err < 0) {
			if (err == -EPIPE)
				err = 0;
			break;
		}

		if (rq.type != EROFS_NBD_CMD_READ) {
			err = erofs_nbd_send_reply_header(ctx->sk.fd,
						rq.cookie, -EIO);
			if (err)
				break;
		}

		erofs_nbd_send_reply_header(ctx->sk.fd, rq.cookie, 0);
		pos = rq.from;
		rem = erofs_io_sendfile(&ctx->sk, &ctx->vd, &pos, rq.len);
		if (rem < 0) {
			err = -errno;
			break;
		}
		err = __erofs_0write(ctx->sk.fd, rem);
		if (err) {
			if (err > 0)
				err = -EIO;
			break;
		}
	}
	erofs_io_close(&ctx->vd);
	erofs_io_close(&ctx->sk);
	return (void *)(uintptr_t)err;
}

static int erofsmount_startnbd(int nbdfd, const char *source)
{
	struct erofsmount_nbd_ctx ctx = {};
	uintptr_t retcode;
	pthread_t th;
	int err, err2;

	err = open(source, O_RDONLY);
	if (err < 0) {
		err = -errno;
		goto out_closefd;
	}
	ctx.vd.fd = err;

	err = erofs_nbd_connect(nbdfd, 9, INT64_MAX >> 9);
	if (err < 0) {
		erofs_io_close(&ctx.vd);
		goto out_closefd;
	}
	ctx.sk.fd = err;

	err = -pthread_create(&th, NULL, erofsmount_nbd_loopfn, &ctx);
	if (err) {
		erofs_io_close(&ctx.vd);
		erofs_io_close(&ctx.sk);
		goto out_closefd;
	}

	err = erofs_nbd_do_it(nbdfd);
	err2 = -pthread_join(th, (void **)&retcode);
	if (!err2 && retcode) {
		erofs_err("NBD worker failed with %s",
		          erofs_strerror(retcode));
		err2 = retcode;
	}
	return err ?: err2;
out_closefd:
	close(nbdfd);
	return err;
}

static char *erofsmount_write_recovery_info(const char *source)
{
	char recp[] = "/var/run/erofs/mountnbd_XXXXXX";
	char *realp;
	int fd, err;
	FILE *f;

	fd = mkstemp(recp);
	if (fd < 0 && errno == ENOENT) {
		err = mkdir("/var/run/erofs", 0700);
		if (err)
			return ERR_PTR(-errno);
		fd = mkstemp(recp);
	}
	if (fd < 0)
		return ERR_PTR(-errno);

	f = fdopen(fd, "w+");
	if (!f) {
		close(fd);
		return ERR_PTR(-errno);
	}

	realp = realpath(source, NULL);
	if (!realp) {
		fclose(f);
		return ERR_PTR(-errno);
	}
	/* TYPE<LOCAL> <SOURCE PATH>\n(more..) */
	err = fprintf(f, "LOCAL %s\n", realp) < 0;
	fclose(f);
	free(realp);
	if (err)
		return ERR_PTR(-ENOMEM);
	return strdup(recp) ?: ERR_PTR(-ENOMEM);
}

static int erofsmount_nbd_fix_backend_linkage(int num, char **recp)
{
	char *newrecp;
	int err;

	newrecp = erofs_nbd_get_identifier(num);
	if (!IS_ERR(newrecp)) {
		err = strlen(newrecp);
		if (newrecp[err - 1] == '\n')
			newrecp[err - 1] = '\0';
		err = strcmp(newrecp, *recp) ? -EFAULT : 0;
		free(newrecp);
		return err;
	}

	if (asprintf(&newrecp, "/var/run/erofs/mountnbd_nbd%d", num) <= 0)
		return -ENOMEM;

	if (rename(*recp, newrecp) < 0) {
		err = -errno;
		free(newrecp);
		return err;
	}
	free(*recp);
	*recp = newrecp;
	return 0;
}

static int erofsmount_startnbd_nl(pid_t *pid, const char *source)
{
	struct erofsmount_nbd_ctx ctx = {};
	int err, num;
	int pipefd[2];

	err = open(source, O_RDONLY);
	if (err < 0)
		return -errno;
	ctx.vd.fd = err;

	err = pipe(pipefd);
	if (err < 0) {
		err = -errno;
		erofs_io_close(&ctx.vd);
		return err;
	}
	if ((*pid = fork()) == 0) {
		char *recp;

		/* Otherwise, NBD disconnect sends SIGPIPE, skipping cleanup */
		if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
			erofs_io_close(&ctx.vd);
			exit(EXIT_FAILURE);
		}
		recp = erofsmount_write_recovery_info(source);
		if (IS_ERR(recp)) {
			erofs_io_close(&ctx.vd);
			exit(EXIT_FAILURE);
		}
		num = -1;
		err = erofs_nbd_nl_connect(&num, 9, INT64_MAX >> 9, recp);
		if (err >= 0) {
			ctx.sk.fd = err;
			err = erofsmount_nbd_fix_backend_linkage(num, &recp);
			if (err) {
				erofs_io_close(&ctx.sk);
			} else {
				err = write(pipefd[1], &num, sizeof(int));
				if (err < 0)
					err = -errno;
				close(pipefd[1]);
				close(pipefd[0]);
				if (err >= sizeof(int)) {
					err = (int)(uintptr_t)erofsmount_nbd_loopfn(&ctx);
					goto out_fork;
				}
			}
		}
		erofs_io_close(&ctx.vd);
out_fork:
		(void)unlink(recp);
		free(recp);
		exit(err ? EXIT_FAILURE : EXIT_SUCCESS);
	}
	close(pipefd[1]);
	err = read(pipefd[0], &num, sizeof(int));
	close(pipefd[0]);
	if (err < sizeof(int))
		return -EPIPE;
	return num;
}

static int erofsmount_reattach(const char *target)
{
	char *identifier, *line, *source, *recp = NULL;
	struct erofsmount_nbd_ctx ctx = {};
	int nbdnum, err;
	struct stat st;
	size_t n;
	FILE *f;

	err = lstat(target, &st);
	if (err < 0)
		return -errno;

	if (!S_ISBLK(st.st_mode) || major(st.st_rdev) != EROFS_NBD_MAJOR)
		return -ENOTBLK;

	nbdnum = erofs_nbd_get_index_from_minor(minor(st.st_rdev));
	if (nbdnum < 0)
		return nbdnum;
	identifier = erofs_nbd_get_identifier(nbdnum);
	if (IS_ERR(identifier))
		identifier = NULL;
	else if (identifier) {
		n = strlen(identifier);
		if (__erofs_unlikely(!n)) {
			free(identifier);
			identifier = NULL;
		} else if (identifier[n - 1] == '\n') {
			identifier[n - 1] = '\0';
		}
	}

	if (!identifier &&
	    (asprintf(&recp, "/var/run/erofs/mountnbd_nbd%d", nbdnum) <= 0)) {
		err = -ENOMEM;
		goto err_identifier;
	}

	f = fopen(identifier ?: recp, "r");
	if (!f) {
		err = -errno;
		free(recp);
		goto err_identifier;
	}
	free(recp);

	line = NULL;
	if ((err = getline(&line, &n, f)) <= 0) {
		err = -errno;
		fclose(f);
		goto err_identifier;
	}
	fclose(f);
	if (err && line[err - 1] == '\n')
		line[err - 1] = '\0';

	source = strchr(line, ' ');
	if (!source) {
		erofs_err("invalid source recorded in recovery file: %s", line);
		err = -EINVAL;
		goto err_line;
	} else {
		*(source++) = '\0';
	}

	if (strcmp(line, "LOCAL")) {
		err = -EOPNOTSUPP;
		erofs_err("unsupported source type %s recorded in recovery file", line);
		goto err_line;
	}

	err = open(source, O_RDONLY);
	if (err < 0) {
		err = -errno;
		goto err_line;
	}
	ctx.vd.fd = err;

	err = erofs_nbd_nl_reconnect(nbdnum, identifier);
	if (err >= 0) {
		ctx.sk.fd = err;
		if (fork() == 0) {
			free(line);
			free(identifier);
			if ((uintptr_t)erofsmount_nbd_loopfn(&ctx))
				return EXIT_FAILURE;
			return EXIT_SUCCESS;
		}
		erofs_io_close(&ctx.sk);
		err = 0;
	}
	erofs_io_close(&ctx.vd);
err_line:
	free(line);
err_identifier:
	free(identifier);
	return err;
}

static int erofsmount_nbd(const char *source, const char *mountpoint,
			  const char *fstype, int flags,
			  const char *options)
{
	bool is_netlink = false;
	char nbdpath[32], *id;
	int num, nbdfd;
	pid_t pid = 0;
	long err;

	if (strcmp(fstype, "erofs")) {
		fprintf(stderr, "unsupported filesystem type `%s`\n",
			mountcfg.fstype);
		return -ENODEV;
	}
	flags |= MS_RDONLY;

	err = erofsmount_startnbd_nl(&pid, source);
	if (err < 0) {
		erofs_info("Fall back to ioctl-based NBD; failover is unsupported");
		num = erofs_nbd_devscan();
		if (num < 0)
			return num;

		(void)snprintf(nbdpath, sizeof(nbdpath), "/dev/nbd%d", num);
		nbdfd = open(nbdpath, O_RDWR);
		if (nbdfd < 0)
			return -errno;

		if ((pid = fork()) == 0)
			return erofsmount_startnbd(nbdfd, source) ?
				EXIT_FAILURE : EXIT_SUCCESS;
		close(nbdfd);
	} else {
		num = err;
		(void)snprintf(nbdpath, sizeof(nbdpath), "/dev/nbd%d", num);
		is_netlink = true;
	}

	while (1) {
		err = erofs_nbd_in_service(num);
		if (err == -ENOENT || err == -ENOTCONN) {
			usleep(50000);
			continue;
		}
		if (err >= 0)
			err = (err != pid ? -EBUSY : 0);
		break;
	}
	if (!err) {
		err = mount(nbdpath, mountpoint, fstype, flags, options);
		if (err < 0)
			err = -errno;

		if (!err && is_netlink) {
			id = erofs_nbd_get_identifier(num);
			if (id == ERR_PTR(-ENOENT))
				id = NULL;

			err = IS_ERR(id) ? PTR_ERR(id) :
				erofs_nbd_nl_reconfigure(num, id, true);
			if (err)
				erofs_warn("failed to turn on autoclear for nbd%d: %s",
					   num, erofs_strerror(err));
		}
	}
	return err;
}

#define EROFSMOUNT_LOOPDEV_RETRIES	3

static int erofsmount_loopmount(const char *source, const char *mountpoint,
				const char *fstype, int flags,
				const char *options)
{
	int fd, dfd, num;
	struct loop_info li = {};
	bool ro = flags & MS_RDONLY;
	char device[32];

	fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	num = ioctl(fd, LOOP_CTL_GET_FREE);
	if (num < 0)
		return -errno;
	close(fd);

	snprintf(device, sizeof(device), "/dev/loop%d", num);
	for (num = 0; num < EROFSMOUNT_LOOPDEV_RETRIES; ++num) {
		fd = open(device, (ro ? O_RDONLY : O_RDWR) | O_CLOEXEC);
		if (fd >= 0)
			break;
		usleep(50000);
	}
	if (fd < 0)
		return -errno;

	dfd = open(source, (ro ? O_RDONLY : O_RDWR));
	if (dfd < 0)
		goto out_err;

	num = ioctl(fd, LOOP_SET_FD, dfd);
	if (num < 0) {
		close(dfd);
		goto out_err;
	}
	close(dfd);

	li.lo_flags = LO_FLAGS_AUTOCLEAR;
	num = ioctl(fd, LOOP_SET_STATUS, &li);
	if (num < 0)
		goto out_err;
	num = mount(device, mountpoint, fstype, flags, options);
	if (num < 0)
		goto out_err;
	close(fd);
	return 0;
out_err:
	close(fd);
	return -errno;
}

int erofsmount_umount(char *target)
{
	char *device = NULL, *mountpoint = NULL;
	struct stat st;
	FILE *mounts;
	int err, fd;
	size_t n;
	char *s;
	bool isblk;

	target = realpath(target, NULL);
	if (!target)
		return -errno;

	err = lstat(target, &st);
	if (err < 0) {
		err = -errno;
		goto err_out;
	}

	if (S_ISBLK(st.st_mode)) {
		isblk = true;
	} else if (S_ISDIR(st.st_mode)) {
		isblk = false;
	} else {
		err = -EINVAL;
		goto err_out;
	}

	mounts = fopen("/proc/mounts", "r");
	if (!mounts) {
		err = -ENOENT;
		goto err_out;
	}

	for (s = NULL; (getline(&s, &n, mounts)) > 0;) {
		bool hit = false;
		char *f1, *f2, *end;

		f1 = s;
		end = strchr(f1, ' ');
		if (end)
			*end = '\0';
		if (isblk && !strcmp(f1, target))
			hit = true;
		if (end) {
			f2 = end + 1;
			end = strchr(f2, ' ');
			if (end)
				*end = '\0';
			if (!isblk && !strcmp(f2, target))
				hit = true;
		}
		if (hit) {
			if (isblk) {
				err = -EBUSY;
				free(s);
				fclose(mounts);
				goto err_out;
			}
			free(device);
			device = strdup(f1);
			if (!mountpoint)
				mountpoint = strdup(f2);
		}
	}
	free(s);
	fclose(mounts);
	if (!isblk && !device) {
		err = -ENOENT;
		goto err_out;
	}

	/* Avoid TOCTOU issue with NBD_CFLAG_DISCONNECT_ON_CLOSE */
	fd = open(isblk ? target : device, O_RDWR);
	if (fd < 0) {
		err = -errno;
		goto err_out;
	}
	if (mountpoint) {
		err = umount(mountpoint);
		if (err) {
			err = -errno;
			close(fd);
			goto err_out;
		}
	}
	err = fstat(fd, &st);
	if (err < 0)
		err = -errno;
	else if (S_ISBLK(st.st_mode) && major(st.st_rdev) == EROFS_NBD_MAJOR)
		err = erofs_nbd_disconnect(fd);
	close(fd);
err_out:
	free(device);
	free(mountpoint);
	free(target);
	return err < 0 ? err : 0;
}

int main(int argc, char *argv[])
{
	int err;

	erofs_init_configure();
	err = erofsmount_parse_options(argc, argv);
	if (err) {
		if (err == -EINVAL)
			fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (mountcfg.mountmode == EROFSMOUNT_MODE_UMOUNT) {
		err = erofsmount_umount(mountcfg.target);
		if (err < 0)
			fprintf(stderr, "Failed to unmount %s: %s\n",
				mountcfg.target, erofs_strerror(err));
		return err ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (mountcfg.mountmode == EROFSMOUNT_MODE_REATTACH) {
		err = erofsmount_reattach(mountcfg.target);
		if (err < 0)
			fprintf(stderr, "Failed to reattach %s: %s\n",
				mountcfg.target, erofs_strerror(err));
		return err ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (mountcfg.backend == EROFSFUSE) {
		err = erofsmount_fuse(mountcfg.device, mountcfg.target,
				      mountcfg.fstype, mountcfg.full_options);
		goto exit;
	}

	if (mountcfg.backend == EROFSNBD) {
		err = erofsmount_nbd(mountcfg.device, mountcfg.target,
				     mountcfg.fstype, mountcfg.flags,
				     mountcfg.options);
		goto exit;
	}

	err = mount(mountcfg.device, mountcfg.target, mountcfg.fstype,
		    mountcfg.flags, mountcfg.options);
	if (err < 0)
		err = -errno;

	if ((err == -ENODEV || err == -EPERM) && mountcfg.backend == EROFSAUTO)
		err = erofsmount_fuse(mountcfg.device, mountcfg.target,
				      mountcfg.fstype, mountcfg.full_options);
	else if (err == -ENOTBLK)
		err = erofsmount_loopmount(mountcfg.device, mountcfg.target,
					   mountcfg.fstype, mountcfg.flags,
					   mountcfg.options);
exit:
	if (err < 0)
		fprintf(stderr, "Failed to mount %s: %s\n",
			mountcfg.fstype, erofs_strerror(err));
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
