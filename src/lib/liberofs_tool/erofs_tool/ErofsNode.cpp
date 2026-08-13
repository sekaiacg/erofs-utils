#include <format>

#include <erofs/inode.h>

#include "LogBase.h"
#include "erofs/ErofsHardlinkHandle.h"
#include "erofs/ErofsNode.h"
#include "erofs/ErofsNodeHelper.h"
#include "erofs/ExtractConfig.h"
#include "erofs/ExtractHelper.h"

namespace skkk::erofs {
	ErofsNode::ErofsNode(const char *path, const erofs_inode &inode) {
		this->path = path;
		this->type = erofs_mode_to_ftype(inode.i_mode);
		this->inode.sbi = inode.sbi;
		this->inode.nid = inode.nid;
		erofs_read_inode_from_disk(&this->inode);
		this->fsConfig = std::format("{} {} {} {:04o}",
		                             path,
		                             this->inode.i_uid,
		                             this->inode.i_gid,
		                             this->inode.i_mode & 0777);
	}

	const std::string &ErofsNode::getPath() const {
		return path;
	}

	uint8_t ErofsNode::getType() const { return type; }

	const char *ErofsNode::getTypeCStr() const {
		switch (erofs_mode_to_ftype(inode.i_mode)) {
			case EROFS_FT_DIR:
				return "DIR";
			case EROFS_FT_REG_FILE:
				return "FILE";
			case EROFS_FT_SYMLINK:
				return "LINK";
			case EROFS_FT_CHRDEV:
				return "CHR";
			case EROFS_FT_BLKDEV:
				return "BLK";
			case EROFS_FT_FIFO:
				return "FIFO";
			case EROFS_FT_SOCK:
				return "SOCK";
			default:
				return "UNKNOWN";
		}
	}

	uint32_t ErofsNode::getMode() const {
		return inode.i_mode;
	}

	uint32_t ErofsNode::getUid() const {
		return inode.i_uid;
	}

	uint32_t ErofsNode::getGid() const {
		return inode.i_gid;
	}

	uint32_t ErofsNode::getNlink() const {
		return inode.i_nlink;
	}

	uint32_t ErofsNode::getNid() const {
		return inode.nid;
	}

	const char *ErofsNode::getDataLayout() const {
		switch (inode.datalayout) {
			case EROFS_INODE_FLAT_PLAIN:
				return "PLAIN";
			case EROFS_INODE_FLAT_INLINE:
				return "INLINE";
			case EROFS_INODE_CHUNK_BASED:
				return "CHUNK";
			case EROFS_INODE_COMPRESSED_FULL:
				return "COMPRESSED_FULL";
			case EROFS_INODE_COMPRESSED_COMPACT:
				return "COMPRESSED_COMPACT";
			default:
				return "UNKNOWN";
		}
	}

	const std::string &ErofsNode::getFsConfig() const { return fsConfig; }

	const std::string &ErofsNode::getSelinuxLabel() const { return selinuxLabel; }

	void ErofsNode::setSelinuxLabel(const std::string &label) { this->selinuxLabel = label; }

	const std::string &ErofsNode::getSelinuxLabelConfig() const {
		return selinuxLabelConfig;
	}

	void ErofsNode::initSelinuxLabelConfig() {
		selinuxLabelConfig.append(path + " " + selinuxLabel);
		handleSpecialSymbols(selinuxLabelConfig);
	}

	void ErofsNode::setCapability(uint64_t cap) { this->capabilities = cap; }

	void ErofsNode::setFsConfigCapabilities(const std::string &capStr) { fsConfig.append(capStr); }

	void ErofsNode::createErofsNode(std::vector<ErofsNode> &nodes, const char *path, erofs_inode &inode) {
		auto &node = nodes.emplace_back(path, inode);
		ErofsNodeHelper::initSecurityContext(node, inode);
		LOGCD("type={:7} dataLayout={:19} {} {}",
		      node.getTypeCStr(),
		      node.getDataLayout(),
		      node.getFsConfig(),
		      node.getSelinuxLabel()
		);
	}

	bool ErofsNode::initExceptionInfo(int errCode) {
		if (errCode && errCode != RET_EXTRACT_FAIL_SKIP) [[unlikely]] {
			extractExceptionInfo = std::format(
				"err={:3}[{:3}] type={:7} dataLayout={:19} name={}",
				errCode,
				strerror(abs(errCode)),
				getTypeCStr(),
				getDataLayout(),
				getPath());
			return true;
		}
		return false;
	}

	void ErofsNode::writeExceptionInfo2FileIfExists(std::ofstream &infoFile) const {
		if (!extractExceptionInfo.empty()) [[unlikely]] {
			infoFile << extractExceptionInfo << "\n";
		}
	}

	int ErofsNode::write2File(const ExtractConfig &config, ErofsHardlinkEntry &erofsHardlinkEntry) const {
		int err = RET_EXTRACT_DONE;
		const std::string &outDir = config.getOutDir();
		std::string _tmp = outDir + path;
		const char *filePath = _tmp.c_str();
		erofs_inode *in = &inode;
		const char *hardlinkSrcPath = erofsHardlinkEntry.erofsHardlinkFind(nid);

		if (hardlinkSrcPath) {
			std::lock_guard lock(*erofsHardlinkEntry.erofsHardlinkLock);
			return ExtractHelper::erofs_extract_hardlink(config, in, (outDir + hardlinkSrcPath).c_str(), filePath);
		}

		switch (type) {
			case EROFS_FT_DIR:
				err = ExtractHelper::erofs_extract_dir(config, filePath);
				break;
			case EROFS_FT_REG_FILE:
				err = ExtractHelper::erofs_extract_file(config, in, filePath);
				break;
			case EROFS_FT_SYMLINK:
				err = ExtractHelper::erofs_extract_symlink(config, in, filePath);
				break;
			case EROFS_FT_CHRDEV:
			case EROFS_FT_BLKDEV:
			case EROFS_FT_FIFO:
			case EROFS_FT_SOCK:
				err = ExtractHelper::erofs_extract_special(config, in, filePath);
				break;
			default:
				err = -EOPNOTSUPP;
		}
		if (!err) ExtractHelper::set_attributes(config, in, filePath);
		return err;
	}
}
