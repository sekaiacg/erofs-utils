#include <cstdlib>
#include <utime.h>

#include <liberofs_sha256.h>
#include <erofs/internal.h>
#include <erofs/xattr.h>

#include "LogBase.h"
#include "Utils.h"
#include "erofs/ExtractHelper.h"

#if defined(_WIN32) || defined(__CYGWIN__)
#include <windef.h>
#include <winbase.h>
#include <fileapi.h>
#endif

namespace skkk::erofs {
	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param config
	 * @param inode
	 * @param outfd
	 * @param digest
	 * @return
	 */
	static int erofs_verify_inode_data(const ExtractConfig &config, erofs_inode *inode, int outfd,
	                                   sha256_state *digest) {
		struct erofs_map_blocks map = {
			.buf = __EROFS_BUF_INITIALIZER,
		};
		bool needdecode = config.check_decomp && !erofs_is_packed_inode(inode);
		int ret = 0;
		bool compressed;
		erofs_off_t pos = 0;
		uint64_t raw_size = 0, buffer_size = 0;
		char *raw = nullptr, *buffer = nullptr;

		compressed = erofs_inode_is_data_compressed(inode->datalayout);
		while (pos < inode->i_size) {
			unsigned int alloc_rawsize;

			map.m_la = pos;
			ret = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_FIEMAP);
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
			if (map.m_la >= inode->i_size || !needdecode)
				continue;

			if (!(map.m_flags & EROFS_MAP_MAPPED)) {
				if (digest) [[unlikely]] {
					static constexpr uint8_t zeros[4096] = {};
					uint64_t remain = map.m_llen;

					while (remain > 0) {
						uint64_t chunk = remain > sizeof(zeros) ? sizeof(zeros) : remain;
						erofs_sha256_process(digest, zeros, chunk);
						remain -= chunk;
					}
				} else if (outfd >= 0) {
					ret = lseek(outfd, map.m_llen, SEEK_CUR);
					if (ret < 0) {
						ret = -errno;
						goto out;
					}
				}
				continue;
			}

			if (map.m_plen > Z_EROFS_PCLUSTER_MAX_SIZE) {
				if (compressed && !(map.m_flags & __EROFS_MAP_FRAGMENT)) {
					ret = -EFSCORRUPTED;
					goto out;
				}
				alloc_rawsize = Z_EROFS_PCLUSTER_MAX_SIZE;
			} else {
				alloc_rawsize = map.m_plen;
			}

			if (alloc_rawsize > raw_size) {
				char *newraw = static_cast<char *>(realloc(raw, alloc_rawsize));

				if (!newraw) {
					ret = -ENOMEM;
					goto out;
				}
				raw = newraw;
				raw_size = alloc_rawsize;
			}

			if (compressed) {
				if (map.m_llen > buffer_size) {
					char *newbuffer;
					buffer_size = map.m_llen;
					newbuffer = static_cast<char *>(realloc(buffer, buffer_size));
					if (!newbuffer) {
						ret = -ENOMEM;
						goto out;
					}
					buffer = newbuffer;
				}
				ret = z_erofs_read_one_data(inode, &map, raw, buffer,
				                            0, map.m_llen, false);
				if (ret)
					goto out;

				if (digest) [[unlikely]]
						erofs_sha256_process(digest, reinterpret_cast<uint8_t *>(buffer), map.m_llen);
				if (outfd >= 0 && write(outfd, buffer, map.m_llen) < 0)
					goto fail_eio;
			} else {
				uint64_t p = 0;

				do {
					uint64_t count = min_t(uint64_t, alloc_rawsize,
					                       map.m_llen);

					ret = erofs_read_one_data(inode, &map, raw, p, count);
					if (ret)
						goto out;

					if (digest) [[unlikely]]
							erofs_sha256_process(digest, reinterpret_cast<uint8_t *>(raw), count);
					if (outfd >= 0 && write(outfd, raw, count) < 0)
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
	 * @param config
	 * @param inode
	 * @param digest
	 * @return
	 */
	static int verify_file_digest(const ExtractConfig &config, erofs_inode *inode,
	                              const uint8_t *digest) {
		uint8_t stored[32 + sizeof("sha256:") - 1];
		int ret = 0;

		ret = __erofs_getxattr(inode, config.digestXattrName.c_str(),
		                       reinterpret_cast<char *>(stored), sizeof(stored), true);
		if (ret == -ENODATA) {
			return 0;
		}
		if (ret < 0)
			return ret;

		if (ret != sizeof(stored) ||
		    memcmp(stored, "sha256:", sizeof("sha256:") - 1) != 0) {
			return -EFSCORRUPTED;
		}

		if (memcmp(digest, stored + sizeof("sha256:") - 1, 32) != 0) {
			return -EFSCORRUPTED;
		}
		return 0;
	}

	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param config
	 * @param inode
	 * @param outfd
	 * @return
	 */
	static int calc_inode_data(const ExtractConfig &config, erofs_inode *inode, int outfd) {
		int ret = 0;

		if (!config.digestXattrName.empty() &&
		    S_ISREG(inode->i_mode) && inode->i_size > 0) [[unlikely]] {
			sha256_state md = {};
			uint8_t out[32] = {};

			erofs_sha256_init(&md);
			ret = erofs_verify_inode_data(config, inode, outfd, &md);
			erofs_sha256_done(&md, out);

			if (ret)
				return ret;
			return verify_file_digest(config, inode, out);
		}
		return erofs_verify_inode_data(config, inode, outfd, nullptr);
	}


	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param dirPath
	 * @return
	 */
	int ExtractHelper::erofs_extract_dir(const ExtractConfig &config, const char *dirPath) {
		bool tryagain = true;

	again:
		if (mkdirs(dirPath, 0700) < 0) {
			struct stat st = {};
			if (config.overwrite && tryagain) {
				if (errno == EEXIST) {
					if (lstat(dirPath, &st) || !S_ISDIR(st.st_mode)) {
						if (unlink(dirPath) < 0) {
							return -errno;
						}
					} else if (chmod(dirPath, 0700) < 0) {
						return -errno;
					}
				}
				tryagain = false;
				goto again;
			}

			if (errno == EEXIST) {
				if (lstat(dirPath, &st) || !S_ISDIR(st.st_mode))
					return -ENOTDIR;
			}
			return -errno;
		}
		return 0;
	}

	/**
	 * Copy from fsck.erofs
	 * Modified
	 *
	 * @param config
	 * @param filePath
	 * @param inode
	 * @return
	 */
	int ExtractHelper::erofs_extract_file(const ExtractConfig &config, erofs_inode *inode, const char *filePath) {
		bool tryagain = true;
		int ret, fd;

	again:
		fd = open(filePath, O_WRONLY | O_CREAT | O_NOFOLLOW |
		                    (config.overwrite ? O_TRUNC : O_EXCL), 0700);
		if (fd < 0) {
			if (config.overwrite && tryagain) {
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
			if (errno == EEXIST && !config.overwrite) {
				return RET_EXTRACT_FAIL_SKIP;
			}
			return -errno;
		}

		ret = calc_inode_data(config, inode, fd);
		close(fd);
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

		if (!CharsetConvert("UTF-8", "UTF-16LE", from, strlen(from), utf16LEBuf, &utf16Len)) {
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
	int ExtractHelper::erofs_extract_symlink(const ExtractConfig &config, erofs_inode *inode, const char *filePath) {
		erofs_vfile vf = {};
		bool tryagain = true;
		char *buf = nullptr;
		int ret;
		erofs_off_t bufsz;

		if (check_add_overflow(inode->i_size, static_cast<erofs_off_t>(1), &bufsz) ||
		    !((buf = static_cast<char *>(malloc(bufsz))))) {
			ret = -ENOMEM;
			goto out;
		}

		ret = erofs_iopen(&vf, inode);
		if (ret)
			goto out;

		ret = erofs_pread(&vf, buf, inode->i_size, 0);
		if (ret) {
			goto out;
		}

		buf[inode->i_size] = '\0';
	again:
#if !(defined(_WIN32) || defined(__CYGWIN__))
		if (symlink(buf, filePath) < 0) {
#else
		// @formatter:off
		if (symlink_cygwin(buf, filePath) < 0) { // @formatter:on
#endif
			if (errno == EEXIST && config.overwrite && tryagain) {
				if (unlink(filePath) < 0) {
					ret = -errno;
					goto out;
				}
				tryagain = false;
				goto again;
			}
			if (errno == EEXIST && !config.overwrite) {
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
	int ExtractHelper::erofs_extract_hardlink(const ExtractConfig &config, erofs_inode *inode, const char *srcPath,
	                                          const char *targetPath) {
		bool tryagain = true;
		int ret = 0;

		if (!fileExists(srcPath))
			ret = erofs_extract_file(config, inode, srcPath);
	again:
		if (strncmp(srcPath, targetPath, strlen(targetPath)) != 0 &&
#if !(defined(_WIN32) || defined(__CYGWIN__))
		    link(srcPath, targetPath) < 0) {
#else
			CreateHardLinkA(targetPath, srcPath, nullptr) != true) {
#endif
			if (errno == EEXIST && config.overwrite && tryagain) {
				if (unlink(targetPath) < 0) {
					ret = -errno;
					goto out;
				}
				tryagain = false;
				goto again;
			}
			if (errno == EEXIST && !config.overwrite) {
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
	int ExtractHelper::erofs_extract_special(const ExtractConfig &config, erofs_inode *inode, const char *filePath) {
		bool tryagain = true;
		int ret = 0;

	again:
		if (mknod(filePath, inode->i_mode, inode->u.i_rdev) < 0) {
			if (errno == EEXIST && config.overwrite && tryagain) {
				if (unlink(filePath) < 0) {
					return -errno;
				}
				tryagain = false;
				goto again;
			}
			if (errno == EEXIST || config.superuser) {
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
	void ExtractHelper::set_attributes(const ExtractConfig &config, erofs_inode *inode, const char *path) {
#ifndef __CYGWIN__
		int ret;
#endif
#ifdef HAVE_UTIMENSAT
		// @formatter:off
		if (utimensat(AT_FDCWD, path, (timespec[]) {
			{
				.tv_sec = static_cast<time_t>(inode->i_mtime),
				.tv_nsec = static_cast<time_t>(inode->i_mtime_nsec)
			},
			{
				.tv_sec = static_cast<time_t>(inode->i_mtime),
				.tv_nsec = static_cast<time_t>(inode->i_mtime_nsec)
			},}, AT_SYMLINK_NOFOLLOW) < 0)
			// @formatter:on
#else
		struct utimbuf ub = {
			.actime = static_cast<time_t>(inode->i_mtime),
			.modtime = static_cast<time_t>(inode->i_mtime)
		};
		if (utime(path, &ub) < 0)
#endif
			LOGCW("failed to set times: {}", path);
#ifndef __CYGWIN__
		if (config.preserve_owner) {
			ret = lchown(path, inode->i_uid, inode->i_gid);
			if (ret < 0)
				LOGCW("failed to change ownership: {}", path);
		}

		if (!S_ISLNK(inode->i_mode)) {
			if (config.preserve_perms)
				ret = chmod(path, inode->i_mode);
			else
				ret = chmod(path, inode->i_mode & ~config.umask);
			if (ret < 0)
				LOGCW("failed to set permissions: {}", path);
		}
#endif
	}
}
