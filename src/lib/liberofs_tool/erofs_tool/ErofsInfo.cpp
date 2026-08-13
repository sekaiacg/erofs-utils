#include <erofs/internal.h>
#include <erofs/xattr.h>

#include "LogBase.h"
#include "erofs/ErofsInfo.h"

namespace skkk::erofs {
	ErofsInfo::ErofsInfo(const ExtractConfig &config)
		: config(config),
		  path(config.getImagePath()) {
	}

	ErofsInfo::~ErofsInfo() {
		erofs_dev_close(&erofsSbi);
	}

	const ExtractConfig &ErofsInfo::getConfig() const {
		return config;
	}

	const std::string &ErofsInfo::getPath() const {
		return path;
	}

	erofs_sb_info &ErofsInfo::getErofsSbi() {
		return erofsSbi;
	}

	bool ErofsInfo::isFeatureCompat(uint32_t flag) const {
		return featureCompat & flag;
	}

	bool ErofsInfo::isFeatureIncompat(uint32_t flag) const {
		return featureIncompat & flag;
	}

	time_t ErofsInfo::getBuildTime() const {
		return buildTime;
	}

	const std::string &ErofsInfo::getBuildTimeStr() const {
		return buildTimeStr;
	}

	const std::string &ErofsInfo::getUuid() const {
		return uuid;
	}

	bool ErofsInfo::isXattrInodeDigest() const {
		return xattrInodeDigest;
	}

	void uuid_unparse_lower(const unsigned char *buf, std::string &uuid) {
		uuid.resize(36);
		sprintf(uuid.data(), "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
		        (buf[0] << 8) | buf[1],
		        (buf[2] << 8) | buf[3],
		        (buf[4] << 8) | buf[5],
		        (buf[6] << 8) | buf[7],
		        (buf[8] << 8) | buf[9],
		        (buf[10] << 8) | buf[11],
		        (buf[12] << 8) | buf[13],
		        (buf[14] << 8) | buf[15]);
	}

	bool ErofsInfo::initVerifyXattrDigests() {
		char *ishare = erofs_xattr_get_ishare_prefix(&erofsSbi);
		if (IS_ERR(ishare)) {
			int err = PTR_ERR(ishare);
			if (config.verifyXattrDigests)
				LOGCE("failed to get ishare prefix: {}", strerror(err));
			goto out;
		}

		if (!ishare) {
			if (config.verifyXattrDigests) {
				LOGCE("image has no inode digest xattrs (was --xattr-inode-digest used during mkfs?)");
				return false;
			}
			goto out;
		}

		xattrInodeDigest = true;
		if (config.verifyXattrDigests) {
			config.digestXattrName = ishare;
		}
		free(ishare);

	out:
		return true;
	}

	bool ErofsInfo::initErofsFile() {
		int ret = 0, err = 0;

		erofsSbi.bdev.offset = config.getOffset();
		ret = erofs_dev_open(&erofsSbi, path.c_str(), O_RDONLY);
		if (ret) {
			LOGCE("failed to open '{}'", path);
			goto exit;
		}

		ret = erofs_read_superblock(&erofsSbi);
		if (ret) {
			LOGCE("failed to read superblock");
			goto exit_dev_close;
		}

		featureCompat = le32_to_cpu(erofsSbi.feature_compat);
		featureIncompat = le32_to_cpu(erofsSbi.feature_incompat);
		buildTime = erofsSbi.epoch + erofsSbi.build_time;
		buildTimeStr = ctime(&buildTime);
		uuid_unparse_lower(erofsSbi.uuid, uuid);

		if (!initVerifyXattrDigests()) {
			goto exit_dev_close;
		}
		return true;

	exit_dev_close:
		erofs_dev_close(&erofsSbi);
	exit:
		return false;
	}

	bool ErofsInfo::initErofsInfo() {
		if (!initErofsFile()) goto out;
		return true;
	out:
		LOGCE("Failed to initialize erofs info");
		return false;
	}
}
