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
#include "../lib/liberofs_oci.h"
#include "../lib/liberofs_gzran.h"

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

/* Device boundary probe */
#define EROFSMOUNT_NBD_DISK_SIZE	(INT64_MAX >> 9)

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

enum erofs_nbd_source_type {
	EROFSNBD_SOURCE_LOCAL,
	EROFSNBD_SOURCE_OCI,
};

static struct erofs_nbd_source {
	enum erofs_nbd_source_type type;
	union {
		const char *device_path;
		struct ocierofs_config ocicfg;
	};
} nbdsrc;

#ifdef OCIEROFS_ENABLED
static int erofsmount_parse_oci_option(const char *option)
{
	struct ocierofs_config *oci_cfg = &nbdsrc.ocicfg;
	char *p;
	long idx;

	p = strstr(option, "oci.blob=");
	if (p != NULL) {
		p += strlen("oci.blob=");
		free(oci_cfg->blob_digest);

		if (oci_cfg->layer_index >= 0) {
			erofs_err("invalid options: oci.blob and oci.layer cannot be set together");
			return -EINVAL;
		}

		if (!strncmp(p, "sha256:", 7)) {
			oci_cfg->blob_digest = strdup(p);
			if (!oci_cfg->blob_digest)
				return -ENOMEM;
		} else if (asprintf(&oci_cfg->blob_digest, "sha256:%s", p) < 0) {
				return -ENOMEM;
		}
	} else {
		p = strstr(option, "oci.layer=");
		if (p != NULL) {
			p += strlen("oci.layer=");
			if (oci_cfg->blob_digest) {
				erofs_err("invalid options: oci.layer and oci.blob cannot be set together");
				return -EINVAL;
			}
			idx = strtol(p, NULL, 10);
			if (idx < 0)
				return -EINVAL;
			oci_cfg->layer_index = (int)idx;
		} else {
			p = strstr(option, "oci.platform=");
			if (p != NULL) {
				p += strlen("oci.platform=");
				free(oci_cfg->platform);
				oci_cfg->platform = strdup(p);
				if (!oci_cfg->platform)
					return -ENOMEM;
			} else {
				p = strstr(option, "oci.username=");
				if (p != NULL) {
					p += strlen("oci.username=");
					free(oci_cfg->username);
					oci_cfg->username = strdup(p);
					if (!oci_cfg->username)
						return -ENOMEM;
				} else {
					p = strstr(option, "oci.password=");
					if (p != NULL) {
						p += strlen("oci.password=");
						free(oci_cfg->password);
						oci_cfg->password = strdup(p);
						if (!oci_cfg->password)
							return -ENOMEM;
					} else {
						p = strstr(option, "oci.tarindex=");
						if (p != NULL) {
							p += strlen("oci.tarindex=");
							free(oci_cfg->tarindex_path);
							oci_cfg->tarindex_path = strdup(p);
							if (!oci_cfg->tarindex_path)
								return -ENOMEM;
						} else {
							p = strstr(option, "oci.zinfo=");
							if (p != NULL) {
								p += strlen("oci.zinfo=");
								free(oci_cfg->zinfo_path);
								oci_cfg->zinfo_path = strdup(p);
								if (!oci_cfg->zinfo_path)
									return -ENOMEM;
							} else {
								return -EINVAL;
							}
						}
					}
				}
			}
		}
	}
	return 0;
}
#else
static int erofsmount_parse_oci_option(const char *option)
{
	return -EINVAL;
}
#endif

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
		int err;

		comma = strchr(s, ',');
		if (comma)
			*comma = '\0';

		if (strncmp(s, "oci", 3) == 0) {
			/* Initialize ocicfg here iff != EROFSNBD_SOURCE_OCI */
			if (nbdsrc.type != EROFSNBD_SOURCE_OCI) {
				nbdsrc.type = EROFSNBD_SOURCE_OCI;
				nbdsrc.ocicfg.layer_index = -1;
			}
			err = erofsmount_parse_oci_option(s);
			if (err < 0)
				return err;
		} else {
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

	nbdsrc.ocicfg.layer_index = -1;

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

struct erofsmount_tarindex_priv {
	struct erofs_vfile tarindex_vf;
	struct erofs_vfile *zinfo_vf;
	u64 tarindex_size;
};

static ssize_t erofsmount_tarindex_pread(struct erofs_vfile *vf, void *buf,
					 size_t count, u64 offset)
{
	struct erofsmount_tarindex_priv *tp;
	ssize_t local_read = 0, remote_read = 0;
	u64 index_part, tardata_part, remote_offset;

	tp = *(struct erofsmount_tarindex_priv **)vf->payload;
	DBG_BUGON(!tp);

	/* Handle device boundary probe requests */
	if (offset >= EROFSMOUNT_NBD_DISK_SIZE)
		return 0;

	if (offset > tp->tarindex_size) {
		remote_offset = offset - tp->tarindex_size;
		index_part = 0;
	} else {
		index_part = min(count, tp->tarindex_size - offset);
		remote_offset = 0;
	}
	tardata_part = count - index_part;
	if (index_part) {
		local_read = erofs_io_pread(&tp->tarindex_vf, buf,
					    index_part, offset);
		if (local_read < 0)
			return local_read;
	}
	if (tardata_part) {
		remote_read = erofs_io_pread(tp->zinfo_vf, buf + local_read,
					     tardata_part, remote_offset);
		if (remote_read < 0)
			return remote_read;
	}
	return local_read + remote_read;
}

static void erofsmount_tarindex_close(struct erofs_vfile *vf)
{
	struct erofsmount_tarindex_priv *tp;

	tp = *(struct erofsmount_tarindex_priv **)vf->payload;
	DBG_BUGON(!tp);

	if (tp->tarindex_size > 0)
		erofs_io_close(&tp->tarindex_vf);
	if (tp->zinfo_vf)
		erofs_io_close(tp->zinfo_vf);
	free(tp);
}

static ssize_t erofsmount_tarindex_sendfile(struct erofs_vfile *vout,
					    struct erofs_vfile *vin,
					    off_t *pos, size_t count)
{
	static char buf[32768];
	ssize_t total_written = 0, ret = 0, written;
	size_t to_read;
	u64 read_offset;

	while (count > 0) {
		to_read = min_t(size_t, count, sizeof(buf));
		read_offset = pos ? *pos : 0;

		ret = erofsmount_tarindex_pread(vin, buf, to_read, read_offset);
		if (ret <= 0) {
			if (ret < 0 && total_written == 0)
				return ret;
			break;
		}

		written = __erofs_io_write(vout->fd, buf, ret);
		if (written < 0) {
			ret = -errno;
			break;
		}
		if (written != ret)
			ret = written;

		total_written += ret;
		count -= ret;
		if (pos)
			*pos += ret;
	}
	return count;
}

static struct erofs_vfops tarindex_vfile_ops = {
	.pread = erofsmount_tarindex_pread,
	.sendfile = erofsmount_tarindex_sendfile,
	.close = erofsmount_tarindex_close,
};

static int load_file_to_buf(const char *path, void **out, unsigned int *out_len)
{
	void *buf = NULL;
	FILE *fp;
	int ret = 0;
	long sz;
	size_t num;

	fp = fopen(path, "rb");
	if (!fp)
		return -errno;

	if (fseek(fp, 0, SEEK_END) != 0) {
		ret = -errno;
		goto out;
	}
	sz = ftell(fp);
	if (sz < 0) {
		ret = -errno;
		goto out;
	}
	rewind(fp);
	if (!sz) {
		ret = -EINVAL;
		goto out;
	}

	buf = malloc((size_t)sz);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	num = fread(buf, 1, (size_t)sz, fp);
	if (num != (size_t)sz) {
		ret = -EIO;
		goto out;
	}
	*out = buf;
	*out_len = (unsigned int)sz;
	buf = NULL;
out:
	if (ret < 0 && buf)
		free(buf);
	fclose(fp);
	return ret;
}

static int erofsmount_init_gzran(struct erofs_vfile **zinfo_vf,
				  const struct ocierofs_config *oci_cfg,
				  const char *zinfo_path)
{
	int err = 0;
	void *zinfo_data = NULL;
	unsigned int zinfo_len = 0;
	struct erofs_vfile *oci_vf = NULL;

	oci_vf = malloc(sizeof(*oci_vf));
	if (!oci_vf) {
		err = -ENOMEM;
		goto cleanup;
	}

	err = ocierofs_io_open(oci_vf, oci_cfg);
	if (err) {
		free(oci_vf);
		goto cleanup;
	}

	/* If no zinfo_path, return oci_vf directly for tar format */
	if (!zinfo_path) {
		*zinfo_vf = oci_vf;
		return 0;
	}

	err = load_file_to_buf(zinfo_path, &zinfo_data, &zinfo_len);
	if (err) {
		erofs_io_close(oci_vf);
		free(oci_vf);
		return err;
	}

	*zinfo_vf = erofs_gzran_zinfo_open(oci_vf, zinfo_data, zinfo_len);
	if (IS_ERR(*zinfo_vf)) {
		err = PTR_ERR(*zinfo_vf);
		*zinfo_vf = NULL;
		erofs_io_close(oci_vf);
		free(oci_vf);
		goto cleanup;
	}

	free(zinfo_data);
	return 0;

cleanup:
	if (zinfo_data)
		free(zinfo_data);
	return err;
}

/*
 * Create tarindex source for gzran+oci hybrid mode with three scenarios:
 * 1. tarindex + zinfo: Remote data is tar.gzip format
 * 2. tarindex only: Remote data is tar format
 */
static int erofsmount_tarindex_open(struct erofs_vfile *out_vf,
				    const struct ocierofs_config *oci_cfg,
				    const char *tarindex_path,
				    const char *zinfo_path)
{
	struct erofsmount_tarindex_priv *tp;
	int err;
	struct stat st;
	struct erofs_vfile *vf;

	tp = calloc(1, sizeof(*tp));
	if (!tp)
		return -ENOMEM;
	vf = &tp->tarindex_vf;
	vf->fd = -1;

	if (tarindex_path) {
		err = open(tarindex_path, O_RDONLY);
		if (err < 0) {
			err = -errno;
			goto err_out;
		}
		vf->fd = err;
		if (fstat(vf->fd, &st) < 0) {
			err = -errno;
			goto err_out;
		}
		tp->tarindex_size = st.st_size;
	}

	err = erofsmount_init_gzran(&tp->zinfo_vf, oci_cfg, zinfo_path);
	if (err)
		goto err_out;
	out_vf->ops = &tarindex_vfile_ops;
	out_vf->fd = 0;
	out_vf->offset = 0;
	*(struct erofsmount_tarindex_priv **)out_vf->payload = tp;
	return 0;

err_out:
	if (vf->fd >= 0)
		close(vf->fd);
	free(tp);
	return err;
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

static int erofsmount_startnbd(int nbdfd, struct erofs_nbd_source *source)
{
	struct erofsmount_nbd_ctx ctx = {};
	uintptr_t retcode;
	pthread_t th;
	int err, err2;

	if (source->type == EROFSNBD_SOURCE_OCI) {
		if (source->ocicfg.tarindex_path || source->ocicfg.zinfo_path) {
			err = erofsmount_tarindex_open(&ctx.vd, &source->ocicfg,
						       source->ocicfg.tarindex_path,
						       source->ocicfg.zinfo_path);
			if (err)
				goto out_closefd;
		} else {
			err = ocierofs_io_open(&ctx.vd, &source->ocicfg);
			if (err)
				goto out_closefd;
		}
	} else {
		err = open(source->device_path, O_RDONLY);
		if (err < 0) {
			err = -errno;
			goto out_closefd;
		}
		ctx.vd.fd = err;
	}

	err = erofs_nbd_connect(nbdfd, 9, EROFSMOUNT_NBD_DISK_SIZE);
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

#ifdef OCIEROFS_ENABLED
static int erofsmount_write_recovery_oci(FILE *f, struct erofs_nbd_source *source)
{
	char *b64cred = NULL;
	int ret;

	if (source->ocicfg.username || source->ocicfg.password) {
		b64cred = ocierofs_encode_userpass(source->ocicfg.username,
						   source->ocicfg.password);
		if (IS_ERR(b64cred))
			return PTR_ERR(b64cred);
	}

	if ((source->ocicfg.tarindex_path || source->ocicfg.zinfo_path) &&
	    source->ocicfg.blob_digest && *source->ocicfg.blob_digest) {
		ret = fprintf(f, "TARINDEX_OCI_BLOB %s %s %s %s %s %s\n",
			      source->ocicfg.image_ref ?: "",
			      source->ocicfg.platform ?: "",
			      source->ocicfg.blob_digest,
			      b64cred ?: "",
			      source->ocicfg.tarindex_path ?: "",
			      source->ocicfg.zinfo_path ?: "");
		free(b64cred);
		return ret < 0 ? -ENOMEM : 0;
	}

	if (source->ocicfg.blob_digest && *source->ocicfg.blob_digest) {
		ret = fprintf(f, "OCI_NATIVE_BLOB %s %s %s %s\n",
			      source->ocicfg.image_ref ?: "",
			      source->ocicfg.platform ?: "",
			      source->ocicfg.blob_digest,
			      b64cred ?: "");
		free(b64cred);
		return ret < 0 ? -ENOMEM : 0;
	}

	if (source->ocicfg.layer_index >= 0) {
		ret = fprintf(f, "OCI_LAYER %s %s %d %s\n",
			      source->ocicfg.image_ref ?: "",
			      source->ocicfg.platform ?: "",
			      source->ocicfg.layer_index,
			      b64cred ?: "");
		free(b64cred);
		return ret < 0 ? -ENOMEM : 0;
	}

	free(b64cred);
	return -EINVAL;
}
#else
static int erofsmount_write_recovery_oci(FILE *f, struct erofs_nbd_source *source)
{
	return -EOPNOTSUPP;
}
#endif

static int erofsmount_write_recovery_local(FILE *f, struct erofs_nbd_source *source)
{
	char *realp;
	int err;

	realp = realpath(source->device_path, NULL);
	if (!realp)
		return -errno;

	/* TYPE<LOCAL> <SOURCE PATH>\n(more..) */
	err = fprintf(f, "LOCAL %s\n", realp) < 0;
	free(realp);
	return err ? -ENOMEM : 0;
}

static char *erofsmount_write_recovery_info(struct erofs_nbd_source *source)
{
	char recp[] = "/var/run/erofs/mountnbd_XXXXXX";
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

	if (source->type == EROFSNBD_SOURCE_OCI)
		err = erofsmount_write_recovery_oci(f, source);
	else
		err = erofsmount_write_recovery_local(f, source);

	fclose(f);
	if (err)
		return ERR_PTR(err);
	return strdup(recp) ?: ERR_PTR(-ENOMEM);
}

#ifdef OCIEROFS_ENABLED
/* Parse input string in format: "image_ref platform layer [b64cred]" */
static int erofsmount_parse_recovery_ocilayer(struct ocierofs_config *oci_cfg,
					      char *source)
{
	char *tokens[4] = {0};
	int token_count = 0;
	char *p = source;
	int err;
	char *endptr;
	unsigned long v;

	while (token_count < 4 && (p = strchr(p, ' ')) != NULL) {
		*p++ = '\0';
		while (*p == ' ')
			p++;
		if (*p == '\0')
			break;
		tokens[token_count++] = p;
	}

	if (token_count < 2)
		return -EINVAL;

	oci_cfg->image_ref = source;
	oci_cfg->platform = tokens[0];

	v = strtoul(tokens[1], &endptr, 10);
	if (endptr == tokens[1] || *endptr != '\0')
		return -EINVAL;
	oci_cfg->layer_index = (int)v;
	free(oci_cfg->blob_digest);
	oci_cfg->blob_digest = NULL;

	if (token_count > 2) {
		err = ocierofs_decode_userpass(tokens[2], &oci_cfg->username,
					       &oci_cfg->password);
		if (err)
			return err;
	}
	return 0;
}

static int erofsmount_parse_recovery_ociblob(struct ocierofs_config *oci_cfg,
					    char *source)
{
	char *tokens[4] = {0};
	int token_count = 0;
	char *p = source;
	int err;

	while (token_count < 4 && (p = strchr(p, ' ')) != NULL) {
		*p++ = '\0';
		while (*p == ' ')
			p++;
		if (*p == '\0')
			break;
		tokens[token_count++] = p;
	}

	if (token_count < 2)
		return -EINVAL;

	oci_cfg->image_ref = source;
	oci_cfg->platform = tokens[0];

	{
		const char *digest = tokens[1];
		const char *hex;

		if (!digest || strncmp(digest, "sha256:", 7) != 0)
			return -EINVAL;
		hex = digest + 7;
		if (strlen(hex) != 64)
			return -EINVAL;
		free(oci_cfg->blob_digest);
		oci_cfg->blob_digest = strdup(digest);
		if (!oci_cfg->blob_digest)
			return -ENOMEM;
	}
	oci_cfg->layer_index = -1;

	if (token_count > 2) {
		err = ocierofs_decode_userpass(tokens[2], &oci_cfg->username,
			       &oci_cfg->password);
		if (err)
			return err;
	}
	return 0;
}

static int erofsmount_reattach_oci(struct erofs_vfile *vf,
				   const char *type, char *source)
{
	struct ocierofs_config oci_cfg = {};
	int err;

	if (!strcmp(type, "OCI_LAYER"))
		err = erofsmount_parse_recovery_ocilayer(&oci_cfg, source);
	else if (!strcmp(type, "OCI_NATIVE_BLOB"))
		err = erofsmount_parse_recovery_ociblob(&oci_cfg, source);
	else
		return -EOPNOTSUPP;

	if (err)
		return err;

	return ocierofs_io_open(vf, &oci_cfg);
}
#else
static int erofsmount_reattach_oci(struct erofs_vfile *vf,
				   const char *type, char *source)
{
	return -EOPNOTSUPP;
}
#endif

static int erofsmount_reattach_gzran_oci(struct erofsmount_nbd_ctx *ctx,
					 char *source)
{
	char *tokens[6] = {0}, *p = source, *space, *oci_source;
	char *meta_path = NULL, *zinfo_path = NULL;
	int token_count = 0, err;
	const char *b64cred;
	struct erofs_vfile temp_vd;
	struct ocierofs_config oci_cfg = {};

	while (token_count < 5) {
		space = strchr(p, ' ');
		if (!space)
			break;

		*space = '\0';
		p = space + 1;
		tokens[token_count++] = p;
	}

	if (token_count < 4)
		return -EINVAL;

	b64cred = (token_count > 2 && tokens[2]) ? tokens[2] : "";

	err = asprintf(&oci_source, "%s %s %s %s",
		       source, tokens[0], tokens[1], b64cred);
	if (err < 0)
		return -ENOMEM;

	err = erofsmount_reattach_oci(&ctx->vd, "OCI_NATIVE_BLOB", oci_source);
	free(oci_source);
	if (err)
		return err;

	temp_vd = ctx->vd;
	oci_cfg.image_ref = strdup(source);
	if (!oci_cfg.image_ref) {
		erofs_io_close(&temp_vd);
		return -ENOMEM;
	}

	if (token_count > 3 && tokens[3] && *tokens[3])
		meta_path = tokens[3];
	if (token_count > 4 && tokens[4] && *tokens[4])
		zinfo_path = tokens[4];

	err = erofsmount_tarindex_open(&ctx->vd, &oci_cfg,
				       meta_path, zinfo_path);
	free(oci_cfg.image_ref);
	erofs_io_close(&temp_vd);
	return err;
}

static int erofsmount_nbd_fix_backend_linkage(int num, char **recp)
{
	char *newrecp;
	int err;

	if (!*recp)
		return 0;
	newrecp = erofs_nbd_get_identifier(num);
	if (!IS_ERR(newrecp) && newrecp) {
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

static int erofsmount_startnbd_nl(pid_t *pid, struct erofs_nbd_source *source)
{
	int pipefd[2], err, num;

	err = pipe(pipefd);
	if (err < 0)
		return -errno;

	if ((*pid = fork()) == 0) {
		struct erofsmount_nbd_ctx ctx = {};
		char *recp;

		/* Otherwise, NBD disconnect sends SIGPIPE, skipping cleanup */
		if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
			exit(EXIT_FAILURE);

		if (source->type == EROFSNBD_SOURCE_OCI) {
			if (source->ocicfg.tarindex_path || source->ocicfg.zinfo_path) {
				err = erofsmount_tarindex_open(&ctx.vd, &source->ocicfg,
							       source->ocicfg.tarindex_path,
							       source->ocicfg.zinfo_path);
				if (err)
					exit(EXIT_FAILURE);
			} else {
				err = ocierofs_io_open(&ctx.vd, &source->ocicfg);
				if (err)
					exit(EXIT_FAILURE);
			}
		} else {
			err = open(source->device_path, O_RDONLY);
			if (err < 0)
				exit(EXIT_FAILURE);
			ctx.vd.fd = err;
		}
		recp = erofsmount_write_recovery_info(source);
		if (IS_ERR(recp)) {
			erofs_io_close(&ctx.vd);
			exit(EXIT_FAILURE);
		}

		num = -1;
		err = erofs_nbd_nl_connect(&num, 9, EROFSMOUNT_NBD_DISK_SIZE, recp);
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
	if (IS_ERR(identifier)) {
		identifier = NULL;
	} else if (identifier && *identifier == '\0') {
		free(identifier);
		identifier = NULL;
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

	if (!strcmp(line, "LOCAL")) {
		err = open(source, O_RDONLY);
		if (err < 0) {
			err = -errno;
			goto err_line;
		}
		ctx.vd.fd = err;
	} else if (!strcmp(line, "TARINDEX_OCI_BLOB")) {
		err = erofsmount_reattach_gzran_oci(&ctx, source);
		if (err)
			goto err_line;
	} else if (!strcmp(line, "OCI_LAYER") || !strcmp(line, "OCI_NATIVE_BLOB")) {
		err = erofsmount_reattach_oci(&ctx.vd, line, source);
		if (err)
			goto err_line;
	} else {
		err = -EOPNOTSUPP;
		erofs_err("unsupported source type %s recorded in recovery file", line);
		goto err_line;
	}

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

static int erofsmount_nbd(struct erofs_nbd_source *source,
			  const char *mountpoint, const char *fstype,
			  int flags, const char *options)
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

			err = IS_ERR(id) ? PTR_ERR(id) :
				erofs_nbd_nl_reconfigure(num, id, true);
			if (err)
				erofs_warn("failed to turn on autoclear for nbd%d: %s",
					   num, erofs_strerror(err));
			if (!IS_ERR(id))
				free(id);
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
		if (nbdsrc.type == EROFSNBD_SOURCE_OCI)
			nbdsrc.ocicfg.image_ref = mountcfg.device;
		else
			nbdsrc.device_path = mountcfg.device;
		err = erofsmount_nbd(&nbdsrc, mountcfg.target,
				     mountcfg.fstype, mountcfg.flags, mountcfg.options);
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
