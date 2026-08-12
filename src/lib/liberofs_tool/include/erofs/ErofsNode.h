#pragma once

#include <fstream>
#include <string>
#include <set>

#include <erofs/internal.h>

#include "Utils.h"
#include "erofs/ErofsHardlinkHandle.h"
#include "erofs/ExtractConfig.h"

namespace skkk::erofs {
	static void handleSpecialSymbols(std::string &str) {
		strReplaceAll(str, ".", "\\.");
		strReplaceAll(str, "+", "\\+");
		strReplaceAll(str, "[", "\\[");
		strReplaceAll(str, "]", "\\]");
		strReplaceAll(str, "*", "\\*");
	}

	static std::set<std::string> otherPathsInRootDir = {
		"/lost+found"
	};

	class ErofsNode {
		std::string path;
		uint8_t type = EROFS_FT_UNKNOWN;
		mutable erofs_inode inode = {};
		std::string fsConfig;
		std::string selinuxLabel;
		std::string selinuxLabelConfig;
		uint64_t capabilities = 0;
		erofs_nid_t nid = {0};
		umode_t i_mode = 0;
		uint32_t i_uid = 0;
		uint32_t i_gid = 0;
		uint64_t i_mtime = 0;
		uint32_t i_mtime_nsec = 0;
		uint32_t i_nlink = 0;
		uint8_t dataLayout = 0;
		std::string extractExceptionInfo;

		public:
			ErofsNode(const char *path, const erofs_inode &inode);

			const std::string &getPath() const;

			uint8_t getType() const;

			const char *getTypeCStr() const;

			uint32_t getMode() const;

			uint32_t getUid() const;

			uint32_t getGid() const;

			uint32_t getNlink() const;

			uint32_t getNid() const;

			const char *getDataLayout() const;

			const std::string &getFsConfig() const;

			const std::string &getSelinuxLabel() const;

			void setSelinuxLabel(const std::string &label);

			const std::string &getSelinuxLabelConfig() const;

			void setCapability(uint64_t cap);

			void setFsConfigCapabilities(const std::string &capStr);

			void initSelinuxLabelConfig();

			static void createErofsNode(std::vector<ErofsNode> &nodes, const char *path, erofs_inode &inode);

			bool initExceptionInfo(int errCode);

			void writeExceptionInfo2FileIfExists(std::ofstream &infoFile) const;

			int write2File(const ExtractConfig &config, ErofsHardlinkEntry &erofsHardlinkEntry) const;
	};
}
