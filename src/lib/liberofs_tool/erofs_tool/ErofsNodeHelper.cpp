#include <format>
#include <private/fs_config.h>

#include "LogBase.h"
#include "erofs/ErofsHardlinkHandle.h"
#include "erofs/ErofsNodeHelper.h"
#include "erofs/ErofsWriter.h"
#include "erofs/common/Buffer.hpp"

namespace skkk::erofs {
	static int doIterNode(erofs_dir_context *ctx) {
		int ret = -1;
		auto *pathCtx = reinterpret_cast<PathIterContext *>(ctx);

		if (ctx->dot_dotdot)
			return 0;

		size_t prev_pos = pathCtx->pos;
		size_t curr_pos = prev_pos;

		if (prev_pos + ctx->de_namelen + 1 >= PATH_MAX) {
			return -EOPNOTSUPP;
		}

		pathCtx->path[curr_pos++] = '/';
		strncpy(pathCtx->path + curr_pos, ctx->dname,
		        ctx->de_namelen);
		curr_pos += ctx->de_namelen;
		pathCtx->path[curr_pos] = '\0';
		pathCtx->pos = curr_pos;

		erofs_inode dir = {
			.sbi = ctx->dir->sbi,
			.nid = ctx->de_nid
		};

		ret = erofs_read_inode_from_disk(&dir);
		if (ret) {
			return ret;
		}
		if (!erofs_is_packed_inode(&dir)) [[likely]] {
			ErofsNode::createErofsNode(pathCtx->nodes, pathCtx->path, dir);
		}

		if (S_ISDIR(dir.i_mode)) {
			PathIterContext pCtx = {
				.ctx.dir = &dir,
				.ctx.cb = doIterNode,
				.ctx.flags = 0,
				.path = pathCtx->path,
				.size = pathCtx->size,
				.pos = curr_pos,
				.nodes = pathCtx->nodes,
			};
			ret = erofs_iterate_dir(&pCtx.ctx, false);
		}
		pathCtx->path[prev_pos] = '\0';
		pathCtx->pos = prev_pos;
		return ret;
	}

	static int initErofsNode(std::vector<ErofsNode> &nodes, erofs_sb_info *sbi) {
		int ret = -1;

		erofs_inode vi = {
			.sbi = sbi,
			.nid = sbi->root_nid,
		};

		ret = erofs_read_inode_from_disk(&vi);
		if (ret) {
			return ret;
		}

		Buffer<char> path{PATH_MAX};
		auto *buf = path.get();
		buf[0] = '/';
		buf[1] = '\0';
		ErofsNode::createErofsNode(nodes, buf, vi);

		if (S_ISDIR(vi.i_mode)) {
			PathIterContext pathCtx = {
				.ctx.dir = &vi,
				.ctx.cb = doIterNode,
				.ctx.flags = 0,
				.path = buf,
				.size = PATH_MAX,
				.pos = 0,
				.nodes = nodes,
			};
			ret = erofs_iterate_dir(&pathCtx.ctx, false);
		}
		return ret;
	}

	void ErofsNodeHelper::initSecurityContext(ErofsNode &node, erofs_inode &inode) {
		char buf[128] = {};
		int len = 0;

		// "security.selinux"
		len = erofs_getxattr(&inode, XATTR_NAME_SELINUX, buf, 128);
		if (len > 0) {
			node.setSelinuxLabel(std::string(buf, len));
			node.initSelinuxLabelConfig();
		}

		// security.capability
		len = erofs_getxattr(&inode, XATTR_NAME_CAPABILITY, buf, 128);
		if (len > 0) {
			uint64_t capabilities = 0;
			auto *fileCapData = reinterpret_cast<struct vfs_cap_data *>(buf);
			// check version size
			switch (le32_to_cpu(fileCapData->magic_etc) & VFS_CAP_REVISION_MASK) {
				case VFS_CAP_REVISION_1:
					if (len != XATTR_CAPS_SZ_1)
						return;
					capabilities = le64_to_cpu(fileCapData->data[0].permitted);
					break;
				case VFS_CAP_REVISION_2:
				case VFS_CAP_REVISION_3:
					if (len == XATTR_CAPS_SZ_2 || len == XATTR_CAPS_SZ_3) {
						capabilities = le64_to_cpu(fileCapData->data[0].permitted) |
						               le64_to_cpu(fileCapData->data[1].permitted) << 32;
					}
					break;
				default:
					return;
			}
			if (capabilities) {
				node.setCapability(capabilities);
				const std::string capStr = std::format(" capabilities=0x{:X}", capabilities);
				node.setFsConfigCapabilities(capStr);
			}
		}
	}

	bool ErofsNodeHelper::initErofsNodeByPath(std::vector<ErofsNode> &nodes, erofs_sb_info &sbi,
	                                          const std::string &path, bool recursive) {
		int ret = -1;
		char targetPath[PATH_MAX] = {};
		erofs_inode vi = {
			.sbi = &sbi,
			.nid = sbi.root_nid
		};

		ret = erofs_ilookup(path.c_str(), &vi);
		if (ret) {
			LOGCE("path not found: '{}'", path);
			goto out;
		}

		ret = erofs_get_pathname(&sbi, vi.nid, targetPath, PATH_MAX);
		if (ret) {
			goto out;
		}

		ErofsNode::createErofsNode(nodes, targetPath, vi);

		if (recursive) {
			if (S_ISDIR(vi.i_mode)) {
				Buffer<char> pathBuf{PATH_MAX};
				auto *buf = pathBuf.get();
				auto pathLen = strlen(targetPath);
				snprintf(buf, PATH_MAX, targetPath, nullptr);
				PathIterContext pathCtx = {
					.ctx.dir = &vi,
					.ctx.cb = doIterNode,
					.ctx.flags = 0,
					.path = buf,
					.size = PATH_MAX,
					.pos = pathLen != 1 ? pathLen : 0,
					.nodes = nodes,
				};
				ret = erofs_iterate_dir(&pathCtx.ctx, false);
			}
			if (ret) {
				LOGCE("failed to initialize ErofsNode, path: '{}'", path);
			}
		}
	out:
		return !nodes.empty();;
	}

	bool ErofsNodeHelper::initErofsNodeByTargets(erofs_sb_info &sbi, std::vector<ErofsNode> &nodes,
	                                             const std::vector<std::string> &targets, bool recursive) {
		for (const auto &target: targets) {
			initErofsNodeByPath(nodes, sbi, target, recursive);
		}
		return !nodes.empty();
	}

	bool ErofsNodeHelper::initErofsNodeByRoot(std::vector<ErofsNode> &nodes, erofs_sb_info &sbi) {
		if (initErofsNode(nodes, &sbi)) {
			LOGCE("failed to initialize ErofsNode!");
			return false;
		}
		return !nodes.empty();
	}

	void ErofsNodeHelper::erofsNodeClassification(std::vector<ErofsNode> &nodes, std::vector<ErofsNode *> &dirs,
	                                              std::vector<ErofsNode *> &files,
	                                              ErofsHardlinkEntry &erofsHardlinkEntry) {
		for (auto &node: nodes) {
			if (node.getType() == EROFS_FT_DIR) {
				dirs.push_back(&node);
			} else if (node.getNlink() > 1) {
				auto nid = node.getNid();
				if (erofsHardlinkEntry.erofsHardlinkFind(nid) == nullptr) {
					if (int ret = erofsHardlinkEntry.erofsHardlinkInsert(node.getNid(), node.getPath().c_str());
						ret < 0) {
						LOGCE("erofsHardlinkInsert: err={}{} path={}",
						      ret,
						      strerror(abs(ret)),
						      node.getPath().c_str());
					}
				}
				files.push_back(&node);
			} else {
				files.push_back(&node);
			}
		}
		LOGCD("erofsNodeClassification done.");
	}
}
