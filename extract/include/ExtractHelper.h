#ifndef EXTRACT_HELPER_H
#define EXTRACT_HELPER_H

#include <string>
#include <vector>

#include "ErofsNode.h"

using namespace std;

#ifndef XATTR_NAME_SELINUX
#define XATTR_NAME_SELINUX "security.selinux"
#endif

#ifndef XATTR_NAME_CAPABILITY
#define XATTR_NAME_CAPABILITY "security.capability"
#endif

namespace skkk {

	/**
	 * erofs_extract_dir
	 * Copy from fsck.erofs
	 *
	 * @param dirPath
	 * @param inode
	 * @return
	 */
	int erofs_extract_dir(const char *dirPath);

	/**
	 * erofs_extract_file
	 * Copy from fsck.erofs
	 *
	 * @param filePath
	 * @param inode
	 * @return
	 */
	int erofs_extract_file(struct erofs_inode *inode, const char *filePath);

	/**
	 * erofs_extract_file
	 * Copy from fsck.erofs
	 *
	 * @param filePath
	 * @param inode
	 * @return
	 */
	int erofs_extract_symlink(struct erofs_inode *inode, const char *filePath);


	/**
	 * erofs_extract_hardlink
	 *
	 * @param srcPath
	 * @param targetPath
	 * @return
	 */
	int erofs_extract_hardlink(erofs_inode *inode, const char *srcPath, const char *targetPath);

	/**
	 * erofs_extract_special
	 * Copy from fsck.erofs
	 *
	 * @param filePath
	 * @param inode
	 * @return
	 */
	int erofs_extract_special(struct erofs_inode *inode, const char *filePath);

	/**
	 * set_attributes
	 * Copy from fsck.erofs
	 *
	 * @param inode
	 * @param path
	 * @return
	 */
	void set_attributes(struct erofs_inode *inode, const char *path);

	/**
	 * writeErofsNode2File
	 *
	 * @param eNode
	 * @param outDir
	 * @return
	 */
	int writeErofsNode2File(ErofsNode *eNode, const string &outDir);

	/**
	 *
	 * Initialize Security context
	 *
	 * @param eNode
	 * @param inode
	 */
	void initSecurityContext(ErofsNode *eNode, struct erofs_inode *inode);

	/**
	 * Initialize all nodes
	 *
	 * @return
	 */
	int initErofsNodeByRoot();

	/**
	 * Initialize the specified node
	 *
	 * @param targetPath
	 * @return
	 */
	int initErofsNodeByTargetPath(const string &targetPath);

}

#endif //EXTRACT_HELPER_H
