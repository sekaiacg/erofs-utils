#include <mutex>
#include <sys/stat.h>
#include <utime.h>
#include <erofs/compress.h>
#include <erofs/dir.h>
#include <private/fs_config.h>

#include "ExtractHelper.h"
#include "ErofsNode.h"
#include "ExtractState.h"
#include "ExtractOperation.h"
#include "ErofsHardlinkHandle.h"
#include "Logging.h"

#if defined(_WIN32) || defined(__CYGWIN__)
#include <windef.h>
#include <winbase.h>
#include <fileapi.h>
#endif

namespace skkk {

	static int doInitNode(erofs_nid_t nid);

	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param ctx
	 * @return
	 */
	static int dirent_iter(struct erofs_dir_context *ctx) {
		int ret;
		size_t prev_pos, curr_pos;

		if (ctx->dot_dotdot)
			return 0;

		prev_pos = eo->iter_pos;
		curr_pos = prev_pos;

		if (prev_pos + ctx->de_namelen >= PATH_MAX) {
			return -EOPNOTSUPP;
		}

		if (eo->iter_path) {
			eo->iter_path[curr_pos++] = '/';
			strncpy(eo->iter_path + curr_pos, ctx->dname,
					ctx->de_namelen);
			curr_pos += ctx->de_namelen;
			eo->iter_path[curr_pos] = '\0';
		} else {
			curr_pos += ctx->de_namelen;
		}
		eo->iter_pos = curr_pos;
		ret = doInitNode(ctx->de_nid);

		if (eo->iter_path)
			eo->iter_path[prev_pos] = '\0';
		eo->iter_pos = prev_pos;
		return ret;
	}

	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param pnid
	 * @param nid
	 * @return
	 */
	static int doInitNode(erofs_nid_t nid) {
		int ret;

		struct erofs_inode inode = {};
		short typeId = EROFS_FT_UNKNOWN;

		inode.nid = nid;
		inode.sbi = &sbi;
		ret = erofs_read_inode_from_disk(&inode);
		if (ret) {
			goto out;
		}
		switch (inode.i_mode & S_IFMT) {
			case S_IFDIR:
				typeId = EROFS_FT_DIR;
				break;
			case S_IFREG:
				if (erofs_is_packed_inode(&inode)) [[unlikely]]
					break;
				typeId = EROFS_FT_REG_FILE;
				break;
			case S_IFLNK:
				typeId = EROFS_FT_SYMLINK;
				break;
			case S_IFCHR:
				typeId = EROFS_FT_CHRDEV;
				break;
			case S_IFBLK:
				typeId = EROFS_FT_BLKDEV;
				break;
			case S_IFIFO:
				typeId = EROFS_FT_FIFO;
				break;
			case S_IFSOCK:
				typeId = EROFS_FT_SOCK;
				break;
			default:
				break;
		}

		{
#ifdef NDEBUG
			ExtractOperation::createErofsNode(eo->iter_path, typeId, &inode);
#else

			const ErofsNode *eNode = ExtractOperation::createErofsNode(eo->iter_path, typeId, &inode);
			LOGCD("type=%s dataLayout=%s %s %s",
				  eNode->getTypeIdCStr(),
				  eNode->getDataLayoutCStr(),
				  eNode->getFsConfig().c_str(),
				  eNode->getSelinuxLabel().c_str()
			);
#endif
		}

		{
			struct erofs_dir_context ctx = {
					.dir = &inode,
					.cb = dirent_iter
			};
			if (S_ISDIR(inode.i_mode)) {
				ret = erofs_iterate_dir(&ctx, false);
			}
		}
out:
		return ret;
	}

	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param inode
	 * @param outfd
	 * @return
	 */
	static int erofs_verify_inode_data(struct erofs_inode *inode, int outfd) {
		struct erofs_map_blocks map = {
				.index = UINT_MAX,
		};
		int ret = 0;
		bool compressed;
		erofs_off_t pos = 0;
		unsigned int raw_size = 0, buffer_size = 0;
		char *raw = nullptr, *buffer = nullptr;

		switch (inode->datalayout) {
			case EROFS_INODE_FLAT_PLAIN:
			case EROFS_INODE_FLAT_INLINE:
			case EROFS_INODE_CHUNK_BASED:
				compressed = false;
				break;
			case EROFS_INODE_COMPRESSED_FULL:
			case EROFS_INODE_COMPRESSED_COMPACT:
				compressed = true;
				break;
			default:
				return -EINVAL;
		}

		while (pos < inode->i_size) {
			unsigned int alloc_rawsize;

			map.m_la = pos;
			if (compressed)
				ret = z_erofs_map_blocks_iter(inode, &map,
											  EROFS_GET_BLOCKS_FIEMAP);
			else
				ret = erofs_map_blocks(inode, &map,
									   EROFS_GET_BLOCKS_FIEMAP);
			if (ret)
				goto out;

			if (!compressed && map.m_llen != map.m_plen) {
				ret = -EFSCORRUPTED;
				goto out;
			}

			/* the last lcluster can be divided into 3 parts */
			if (map.m_la + map.m_llen > inode->i_size)
				map.m_llen = inode->i_size - map.m_la;

			pos += map.m_llen;

			/* should skip decomp? */
			if (!(map.m_flags & EROFS_MAP_MAPPED) || !eo->check_decomp)
				continue;

			if (map.m_plen > Z_EROFS_PCLUSTER_MAX_SIZE) {
				if (compressed) {
					ret = -EFSCORRUPTED;
					goto out;
				}
				alloc_rawsize = Z_EROFS_PCLUSTER_MAX_SIZE;
			} else {
				alloc_rawsize = map.m_plen;
			}

			if (alloc_rawsize > raw_size) {
				char *newraw = (char *) realloc(raw, alloc_rawsize);

				if (!newraw) {
					ret = -ENOMEM;
					goto out;
				}
				raw = newraw;
				raw_size = alloc_rawsize;
			}

			if (compressed) {
				if (map.m_llen > buffer_size) {
					buffer_size = map.m_llen;
					buffer = (char *) realloc(buffer, buffer_size);
					BUG_ON(!buffer);
				}
				ret = z_erofs_read_one_data(inode, &map, raw, buffer,
											0, map.m_llen, false);
				if (ret)
					goto out;

				if (outfd > 0 && write(outfd, buffer, map.m_llen) < 0)
					goto fail_eio;
			} else {
				u64 p = 0;

				do {
					u64 count = min_t(u64, alloc_rawsize,
									  map.m_llen);

					ret = erofs_read_one_data(inode, &map, raw, p, count);
					if (ret)
						goto out;

					if (outfd > 0 && write(outfd, raw, count) < 0)
						goto fail_eio;
					map.m_llen -= count;
					p += count;
				} while (map.m_llen);
			}
		}

out:
		if (raw)
			free(raw);
		if (buffer)
			free(buffer);
		return ret < 0 ? ret : 0;

fail_eio:
		ret = -EIO;
		goto out;
	}

	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param dirPath
	 * @return
	 */
	int erofs_extract_dir(const char *dirPath) {

		if (mkdirs(dirPath, 0700) < 0) {
			struct stat st = {};

			if (errno != EEXIST) {
				return -errno;
			}

			if (lstat(dirPath, &st) ||
				!S_ISDIR(st.st_mode)) {
				return -ENOTDIR;
			}

			if (chmod(dirPath, 0700) < 0) {
				return -errno;
			}
		}
		return 0;
	}

	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param filePath
	 * @param inode
	 * @return
	 */
	int erofs_extract_file(struct erofs_inode *inode, const char *filePath) {
		bool tryagain = true;
		int ret, fd;

again:
		fd = open(filePath,
				  O_WRONLY | O_CREAT | O_NOFOLLOW |
				  (eo->overwrite ? O_TRUNC : O_EXCL), 0700);
		if (fd < 0) {
			if (eo->overwrite && tryagain) {
				if (errno == EISDIR) {
					if (rmdir(filePath) < 0) {
						return -EISDIR;
					}
				} else if (errno == EACCES &&
						   chmod(filePath, 0700) < 0) {
					return -errno;
				}
				tryagain = false;
				goto again;
			}
			if (errno == EEXIST && !eo->overwrite) {
				return RET_EXTRACT_FAIL_SKIP;
			}
			return -errno;
		}

		/* verify data chunk layout */
		ret = erofs_verify_inode_data(inode, fd);
		if (ret)
			return ret;

		if (close(fd))
			return -errno;
		return ret;

	}

#if defined(_WIN32) || defined(__CYGWIN__)
	const char CYGLINK_MAGIC[] = "!<symlink>";

	int symlink_cygwin(const char *from, const char *to) {
		int fd;
		size_t utf16Len = PATH_MAX;
		char utf16LEBuf[PATH_MAX] = {0};

		fd = open(to,
				  O_WRONLY | O_CREAT | O_NOFOLLOW | O_EXCL,
				  0700);
		if (fd < 0) {
			return -1;
		}

		if (!CharsetConvert("UTF-8",
				  "UTF-16LE",
				  from, strlen(from),
				  utf16LEBuf, &utf16Len)) {
			return -1;
		}

		write(fd, CYGLINK_MAGIC, strlen(CYGLINK_MAGIC));
		write(fd, "\xFF\xFE", 2); //UTF16 BOM (little endian)
		write(fd, utf16LEBuf, PATH_MAX - utf16Len);
		write(fd, "\x0\x0", 2);
		close(fd);
		SetFileAttributesA(to, FILE_ATTRIBUTE_SYSTEM);
		return 0;
	}

#endif

	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param filePath
	 * @param inode
	 * @return
	 */
	int erofs_extract_symlink(erofs_inode *inode, const char *filePath) {
		bool tryagain = true;
		int ret;
		char *buf;

		buf = (char *) malloc(inode->i_size + 1);
		if (!buf) {
			ret = -ENOMEM;
			goto out;
		}

		ret = erofs_pread(inode, buf, inode->i_size, 0);
		if (ret) {
			goto out;
		}

		buf[inode->i_size] = '\0';
again:
#if !(defined(_WIN32) || defined(__CYGWIN__))
		if (symlink(buf, filePath) < 0) {
#else
		if (symlink_cygwin(buf, filePath) < 0) {
#endif
			if (errno == EEXIST && eo->overwrite && tryagain) {
				if (unlink(filePath) < 0) {
					ret = -errno;
					goto out;
				}
				tryagain = false;
				goto again;
			}
			if (errno == EEXIST && !eo->overwrite) {
				return RET_EXTRACT_FAIL_SKIP;
			}
			ret = -errno;
		}
out:
		if (buf)
			free(buf);
		return ret;
	}

	/**
	 * erofs_extract_hardlink
	 *
	 * @param srcPath
	 * @param targetPath
	 * @return
	 */
	int erofs_extract_hardlink(erofs_inode *inode, const char *srcPath, const char *targetPath) {
		bool tryagain = true;
		int ret = 0;

		if (!fileExists(srcPath))
			ret = erofs_extract_file(inode, srcPath);
again:
		if (strncmp(srcPath, targetPath, strlen(targetPath)) != 0 &&
#if !(defined(_WIN32) || defined(__CYGWIN__))
			link(srcPath, targetPath) < 0) {
#else
			CreateHardLinkA(targetPath, srcPath, nullptr) != true) {
#endif
			if (errno == EEXIST && eo->overwrite && tryagain) {
				if (unlink(targetPath) < 0) {
					ret = -errno;
					goto out;
				}
				tryagain = false;
				goto again;
			}
			if (errno == EEXIST && !eo->overwrite) {
				return RET_EXTRACT_FAIL_SKIP;
			}
			ret = -errno;
		}
out:
		return ret;
	}

	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param filePath
	 * @param inode
	 * @return
	 */
	int erofs_extract_special(erofs_inode *inode, const char *filePath) {

		bool tryagain = true;
		int ret = 0;

again:
		if (mknod(filePath, inode->i_mode, inode->u.i_rdev) < 0) {
			if (errno == EEXIST && eo->overwrite && tryagain) {
				if (unlink(filePath) < 0) {
					return -errno;
				}
				tryagain = false;
				goto again;
			}
			if (errno == EEXIST || eo->superuser) {
				ret = -errno;
			} else {
				ret = -ECANCELED;
			}
		}
		return ret;
	}

	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param inode
	 * @param path
	 */
	void set_attributes(struct erofs_inode *inode, const char *path) {
#ifndef __CYGWIN__
		int ret;
#endif
#ifdef HAVE_UTIMENSAT
		if (utimensat(AT_FDCWD, path, (struct timespec[]) {
				{
						.tv_sec =  (time_t) inode->i_mtime,
						.tv_nsec = (time_t) inode->i_mtime_nsec
				},
				{
						.tv_sec = (time_t) inode->i_mtime,
						.tv_nsec = (time_t) inode->i_mtime_nsec
				},
		}, AT_SYMLINK_NOFOLLOW) < 0)
#else
		struct utimbuf ub = {
				.actime = (time_t) inode->i_mtime,
				.modtime = (time_t) inode->i_mtime
		};
		if (utime(path, &ub) < 0)
#endif
			LOGCW("failed to set times: %s", path);
#ifndef __CYGWIN__
		if (!S_ISLNK(inode->i_mode)) {
			if (eo->preserve_perms)
				ret = chmod(path, inode->i_mode);
			else
				ret = chmod(path, inode->i_mode & ~eo->umask);
			if (ret < 0)
				LOGCW("failed to set permissions: %s", path);
		}

		if (eo->preserve_owner) {
			ret = lchown(path, inode->i_uid, inode->i_gid);
			if (ret < 0)
				LOGCW("failed to change ownership: %s", path);
		}
#endif
	}

	int writeErofsNode2File(ErofsNode *eNode, const string &outDir) {
		int err = RET_EXTRACT_DONE;
		string _tmp = outDir + eNode->getPath();
		const char *filePath = _tmp.c_str();
		erofs_inode *inode = eNode->getErofsInode();
		const char *hardlinkSrcPath;

		hardlinkSrcPath = erofsHardlinkFind(inode->nid);
		if (hardlinkSrcPath) {
			unique_lock lock(erofsHardlinkLock);
			return erofs_extract_hardlink(inode, (outDir + hardlinkSrcPath).c_str(), filePath);
		}

		switch (eNode->getTypeId()) {
			case EROFS_FT_DIR:
				err = erofs_extract_dir(filePath);
				break;
			case EROFS_FT_REG_FILE:
				err = erofs_extract_file(inode, filePath);
				break;
			case EROFS_FT_SYMLINK:
				err = erofs_extract_symlink(inode, filePath);
				break;
			case EROFS_FT_CHRDEV:
			case EROFS_FT_BLKDEV:
			case EROFS_FT_FIFO:
			case EROFS_FT_SOCK:
				err = erofs_extract_special(inode, filePath);
				break;
		}
		if (!err) set_attributes(inode, filePath);
		return err;
	}

	void initSecurityContext(ErofsNode *eNode, struct erofs_inode *inode) {
		char buf[128] = {0};
		int len;

		// "security.selinux"
		len = erofs_getxattr(inode, XATTR_NAME_SELINUX, buf, 128);
		if (len > 0) {
			eNode->setSelinuxLabel(string(buf, len));
		}

		// security.capability
		len = erofs_getxattr(inode, XATTR_NAME_CAPABILITY, buf, 128);
		if (len > 0) {
			uint64_t capabilities = 0;
			auto *fileCapData = (struct vfs_cap_data *) buf;
			uint32_t cap_version = le32_to_cpu(fileCapData->magic_etc) & VFS_CAP_REVISION_MASK;
			// check version size
			switch (cap_version) {
				case VFS_CAP_REVISION_1:
					if (len != XATTR_CAPS_SZ_1)
						return;
					capabilities = le32_to_cpu(fileCapData->data[0].permitted);
					break;
				case VFS_CAP_REVISION_2:
					if (len != XATTR_CAPS_SZ_2)
						return;
					capabilities = (uint64_t) le32_to_cpu(fileCapData->data[0].permitted) |
								   ((uint64_t) le32_to_cpu(fileCapData->data[1].permitted)) << 32;
					break;
				default:
					return;
			}

			if (capabilities) {
				eNode->setCapability(capabilities);
				char capBuf[32] = {0};
				snprintf(capBuf, 32, " capabilities=0x%" PRIX64, capabilities);
				eNode->setFsConfigCapabilities(capBuf);
			}
		}
	}

	int initErofsNodeByRoot() {
		int rc = RET_EXTRACT_DONE, err;
		eo->iter_path = (char *) malloc(PATH_MAX);
		memset(eo->iter_path, 0, PATH_MAX);

		// root is '/'
		eo->iter_path[0] = '/';
		eo->iter_pos = 0;

		err = doInitNode(sbi.root_nid);
		if (err) {
			rc = RET_EXTRACT_INIT_NODE_FAIL;
			LOGCE("failed to initialize ErofsNode!");
		}
		if (eo->iter_path) free(eo->iter_path);
		eo->iter_pos = 0;
		return rc;
	}

	int initErofsNodeByTargetPath(const string &targetPath) {
		char pathnameBuf[PATH_MAX] = {0};
		int rc = RET_EXTRACT_INIT_NODE_FAIL, err;
		if (targetPath.empty()) return RET_EXTRACT_INIT_NODE_FAIL;

		eo->iter_path = (char *) malloc(PATH_MAX);
		memset(eo->iter_path, 0, PATH_MAX);

		// find targetPath
		struct erofs_inode vi = {
				.sbi = &sbi,
				.nid = sbi.root_nid
		};

		err = erofs_ilookup(targetPath.c_str(), &vi);
		if (err) {
			LOGCE("path not found: '%s'", targetPath.c_str());
			goto exit;
		}

		err = erofs_get_pathname(&sbi, vi.nid, pathnameBuf, PATH_MAX);
		if (err) {
			goto exit;
		}
		eo->iter_pos = snprintf(eo->iter_path, PATH_MAX, pathnameBuf, nullptr);

		err = doInitNode(vi.nid);
		if (err) {
			LOGCE("failed to initialize ErofsNode, path: '%s'", targetPath.c_str());
			goto exit;
		}

		rc = RET_EXTRACT_DONE;
exit:
		if (eo->iter_path) free(eo->iter_path);
		eo->iter_pos = 0;
		return rc;
	}
}
