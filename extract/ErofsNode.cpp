#include "ErofsNode.h"
#include "ExtractHelper.h"
#include "ExtractState.h"

#define FS_CONFIG_BUF_SIZE (PATH_MAX + 256)

namespace skkk {

	ErofsNode::ErofsNode(const char *path, short typeId, struct erofs_inode *inode) {
		this->path = path;
		this->typeId = typeId;
		this->nid = inode->nid;
		this->i_mode = inode->i_mode;
		this->i_uid = inode->i_uid;
		this->i_gid = inode->i_gid;
		this->i_mtime = inode->i_mtime;
		this->i_mtime_nsec = inode->i_mtime_nsec;
		this->dataLayout = inode->datalayout;
		char buf[FS_CONFIG_BUF_SIZE] = {0};
		snprintf(buf, FS_CONFIG_BUF_SIZE, "%s %u %u %04o",
				 path,
				 inode->i_uid,
				 inode->i_gid,
				 inode->i_mode & 0777
		);
		this->fsConfig = buf;
		this->inode = new erofs_inode;
		this->inode->nid = inode->nid;
		erofs_read_inode_from_disk(this->inode);
	}

	ErofsNode::~ErofsNode() { delete inode; }

	const string &ErofsNode::getPath() const { return path; }

	short ErofsNode::getTypeId() const { return typeId; }

	erofs_inode *ErofsNode::getErofsInode() const { return inode; }

	const char *ErofsNode::getTypeIdCStr() const {
		switch (typeId) {
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
		}
		return "UNKNOWN";
	}

	const char *ErofsNode::getDataLayoutCStr() const {
		switch (dataLayout) {
			case EROFS_INODE_FLAT_PLAIN:
				return "PLAIN";
			case EROFS_INODE_FLAT_INLINE:
				return "INLINE";
			case EROFS_INODE_CHUNK_BASED:
				return "CHUNK";
			case EROFS_INODE_FLAT_COMPRESSION_LEGACY:
				return "COMPRESSION_LEGACY";
			case EROFS_INODE_FLAT_COMPRESSION:
				return "COMPRESSION";
		}
		return "UNKNOWN";
	}

	const string &ErofsNode::getFsConfig() const { return fsConfig; }

	const string &ErofsNode::getSeLabel() const { return seContext; }

	void ErofsNode::setSeContext(const string &_seContext) { this->seContext = _seContext; }

#ifdef WITH_ANDROID

	uint64_t ErofsNode::getCapability() const { return capabilities; }

	void ErofsNode::setCapability(uint64_t _capabilities) { this->capabilities = _capabilities; }

	void ErofsNode::setFsConfigCapabilities(const char *capabilitiesStr) { fsConfig.append(capabilitiesStr); }

#endif

	bool ErofsNode::initExceptionInfo(int err) {
		if (err && err != RET_EXTRACT_FAIL_SKIP) [[unlikely]] {
			char buf[FS_CONFIG_BUF_SIZE] = {0};
			snprintf(buf, FS_CONFIG_BUF_SIZE, "err=%d type=%s dataLayout=%s name=%s",
					 err,
					 getTypeIdCStr(),
					 getDataLayoutCStr(),
					 getPath().c_str()
			);
			extractExceptionInfo = buf;
			return true;
		}
		return false;
	}

	void
	ErofsNode::writeFsConfigAndSeContext2File(FILE *fsConfigFile, FILE *seContextFile, const char *imgBaseName) const {
		if (path == "/") [[unlikely]] {
			fprintf(fsConfigFile, "%s\n", fsConfig.c_str());
			fprintf(seContextFile, "/%s %s\n", imgBaseName, seContext.c_str());
		}
		fprintf(fsConfigFile, "%s%s\n", imgBaseName, fsConfig.c_str());
		string newPath = path;
		handleSpecialSymbols(newPath);
		fprintf(seContextFile, "/%s%s %s\n", imgBaseName, newPath.c_str(), seContext.c_str());
	}

	int ErofsNode::writeNodeEntity2File(const string &outDir) {
		int err = RET_EXTRACT_DONE;
		string _tmp = outDir + path;
		const char *filePath = _tmp.c_str();
		switch (this->typeId) {
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

	void ErofsNode::writeExceptionInfo2FileIfExists(FILE *infoFile) const {
		if (!extractExceptionInfo.empty()) [[unlikely]] {
			fprintf(infoFile, "%s\n", extractExceptionInfo.c_str());
		}
	}
}
