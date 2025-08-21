// SPDX-License-Identifier: GPL-2.0+
#define _GNU_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>
#include "erofs/config.h"
#include "erofs/print.h"
#include "erofs/err.h"
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

enum erofs_backend_drv {
	EROFSAUTO,
	EROFSLOCAL,
	EROFSFUSE,
};

static struct erofsmount_cfg {
	char *device;
	char *mountpoint;
	char *options;
	char *full_options;		/* used for erofsfuse */
	char *fstype;
	long flags;
	enum erofs_backend_drv backend;
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
		{0, 0, 0, 0},
	};
	char *dot;
	int opt;

	while ((opt = getopt_long(argc, argv, "Nfno:st:v",
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
				} else {
					erofs_err("invalid filesystem subtype `%s`", dot + 1);
					return -EINVAL;
				}
				*dot = '\0';
			}
			mountcfg.fstype = optarg;
			break;
		default:
			return -EINVAL;
		}
	}

	if (optind >= argc) {
		erofs_err("missing argument: DEVICE");
		return -EINVAL;
	}

	mountcfg.device = strdup(argv[optind++]);
	if (!mountcfg.device)
		return -ENOMEM;

	if (optind >= argc) {
		erofs_err("missing argument: MOUNTPOINT");
		return -EINVAL;
	}

	mountcfg.mountpoint = strdup(argv[optind++]);
	if (!mountcfg.mountpoint)
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

#define EROFSMOUNT_LOOPDEV_RETRIES	3

int erofsmount_loopmount(const char *source, const char *mountpoint,
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

	if (mountcfg.backend == EROFSFUSE) {
		err = erofsmount_fuse(mountcfg.device, mountcfg.mountpoint,
				      mountcfg.fstype, mountcfg.full_options);
		goto exit;
	}

	err = mount(mountcfg.device, mountcfg.mountpoint, mountcfg.fstype,
		    mountcfg.flags, mountcfg.options);
	if (err < 0)
		err = -errno;

	if ((err == -ENODEV || err == -EPERM) && mountcfg.backend == EROFSAUTO)
		err = erofsmount_fuse(mountcfg.device, mountcfg.mountpoint,
				      mountcfg.fstype, mountcfg.full_options);
	else if (err == -ENOTBLK)
		err = erofsmount_loopmount(mountcfg.device, mountcfg.mountpoint,
					   mountcfg.fstype, mountcfg.flags,
					   mountcfg.options);
exit:
	if (err < 0)
		fprintf(stderr, "Failed to mount %s: %s\n",
			mountcfg.fstype, erofs_strerror(err));
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
