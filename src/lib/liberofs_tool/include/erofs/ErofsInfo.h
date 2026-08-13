#pragma once

#include "erofs/ExtractConfig.h"

namespace skkk::erofs {
	class ErofsInfo {
		const ExtractConfig &config;
		std::string path;
		erofs_sb_info erofsSbi = {};
		time_t buildTime = 0;
		std::string buildTimeStr;
		std::string uuid;
		uint32_t featureCompat = 0;
		uint32_t featureIncompat = 0;
		bool xattrInodeDigest = false;

		public:
			explicit ErofsInfo(const ExtractConfig &config);

			virtual ~ErofsInfo();

			const ExtractConfig &getConfig() const;

			const std::string &getPath() const;

			erofs_sb_info &getErofsSbi();

			bool isFeatureCompat(uint32_t flag) const;

			bool isFeatureIncompat(uint32_t flag) const;

			time_t getBuildTime() const;

			const std::string &getBuildTimeStr() const;

			const std::string &getUuid() const;

			bool isXattrInodeDigest() const;

			virtual bool initVerifyXattrDigests();

			virtual bool initErofsFile();

			virtual bool initErofsInfo();
	};
}
