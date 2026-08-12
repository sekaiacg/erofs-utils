#pragma once

#include "erofs/ExtractConfig.h"

namespace skkk::erofs {
	class ExtractHelper {
		public:
			/**
			 * erofs_extract_dir
			 * Copy from fsck.erofs
			 *
			 * @param dirPath
			 * @param inode
			 * @return
			 */
			static int erofs_extract_dir(const ExtractConfig &config, const char *dirPath);

			/**
			 * erofs_extract_file
			 * Copy from fsck.erofs
			 *
			 * @param config
			 * @param filePath
			 * @param inode
			 * @return
			 */
			static int erofs_extract_file(const ExtractConfig &config, erofs_inode *inode, const char *filePath);

			/**
			 * erofs_extract_file
			 * Copy from fsck.erofs
			 *
			 * @param config
			 * @param filePath
			 * @param inode
			 * @return
			 */
			static int erofs_extract_symlink(const ExtractConfig &config, erofs_inode *inode, const char *filePath);


			/**
			 * erofs_extract_hardlink
			 *
			 * @param config
			 * @param srcPath
			 * @param targetPath
			 * @return
			 */
			static int erofs_extract_hardlink(const ExtractConfig &config, erofs_inode *inode, const char *srcPath,
			                                  const char *targetPath);

			/**
			 * erofs_extract_special
			 * Copy from fsck.erofs
			 *
			 * @param config
			 * @param filePath
			 * @param inode
			 * @return
			 */
			static int erofs_extract_special(const ExtractConfig &config, erofs_inode *inode, const char *filePath);

			/**
			 * set_attributes
			 * Copy from fsck.erofs
			 *
			 * @param config
			 * @param inode
			 * @param path
			 * @return
			 */
			static void set_attributes(const ExtractConfig &config, erofs_inode *inode, const char *path);
	};
}
