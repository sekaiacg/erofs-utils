#pragma once

#include <string>
#include <vector>

#include <erofs/dir.h>

#include "erofs/ErofsNode.h"

namespace skkk::erofs {
#ifndef XATTR_NAME_SELINUX
#define XATTR_NAME_SELINUX "security.selinux"
#endif

#ifndef XATTR_NAME_CAPABILITY
#define XATTR_NAME_CAPABILITY "security.capability"
#endif

	struct PathIterContext {
		erofs_dir_context ctx = {};
		char *path = nullptr;
		size_t size = 0;
		size_t pos = 0;
		std::vector<ErofsNode> &nodes;
	};

	class ErofsNodeHelper {
		public:
			static void initSecurityContext(ErofsNode &node, erofs_inode &inode);

			static bool initErofsNodeByPath(std::vector<ErofsNode> &nodes, erofs_sb_info &sbi,
			                                const std::string &path, bool recursive);

			static bool initErofsNodeByTargets(erofs_sb_info &sbi, std::vector<ErofsNode> &nodes,
			                                   const std::vector<std::string> &targets,
			                                   bool recursive);

			static bool initErofsNodeByRoot(std::vector<ErofsNode> &nodes, erofs_sb_info &sbi);

			static void erofsNodeClassification(std::vector<ErofsNode> &nodes, std::vector<ErofsNode *> &dirs,
			                                    std::vector<ErofsNode *> &files,
			                                    ErofsHardlinkEntry &erofsHardlinkEntry);
	};
}
