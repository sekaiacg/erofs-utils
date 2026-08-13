#pragma once

#include <string>
#include <thread>
#include <vector>

#include <erofs/internal.h>

namespace skkk::erofs {
	enum ExtractResult {
		RET_EXTRACT_DONE = 0,
		RET_EXTRACT_CONFIG_DONE = 1,
		RET_EXTRACT_CONFIG_FAIL,
		RET_EXTRACT_INIT_FAIL,
		RET_EXTRACT_INIT_NODE_FAIL,
		RET_EXTRACT_OUTDIR_ROOT,
		RET_EXTRACT_OPEN_FILE,
		RET_EXTRACT_CREATE_DIR_FAIL,
		RET_EXTRACT_CREATE_FILE_FAIL,
		RET_EXTRACT_THREAD_NUM_ERROR,
		RET_EXTRACT_FAIL_SKIP,
		RET_EXTRACT_FAIL_EXIT
	};

	class ExtractConfig {
		protected:
			std::string imagePath;
			std::string imageBaseName;
			uint64_t offset = 0;
			std::string outDir;
			std::string configDir;
			std::string targetPath;
			std::vector<std::string> targets;
			std::string targetConfigPath;

		public:
			mode_t umask = ::umask(0);
			bool superuser = geteuid() == 0;
			bool preserve_owner = superuser;
			bool preserve_perms = superuser;
			bool verifyXattrDigests = false;
			mutable std::string digestXattrName;

		public:
#if !defined(_WIN32)
			static constexpr bool isWin = false;
#else
			static constexpr bool isWin = true;
#endif
			bool isPrintAll = false;
			bool isPrintTarget = false;
			bool isExtractAll = false;
			bool isExtractTarget = false;
			bool isExtractConfig = false;
			bool isExtractTargetConfig = false;
			bool targetRecursive = false;
			bool overwrite = false;
			bool check_decomp = false;
			bool isExcludeMode = false;
			bool isSilent = false;
			uint32_t threadNum = 0;
			uint32_t hardwareConcurrency = std::thread::hardware_concurrency();
			uint32_t limitHardwareConcurrency = hardwareConcurrency * 3;

		public:
			ExtractConfig() = default;

			virtual ~ExtractConfig() = default;

			virtual const std::string &getImagePath() const;

			virtual void setImagePath(const std::string &path);

			virtual const std::string &getImageBaseName() const;

			virtual uint64_t getOffset() const;

			virtual void setOffset(uint64_t offset);

			virtual const std::string &getOutDir() const;

			virtual void setOutDir(const std::string &path);

			virtual std::string getConfigDir() const;

			virtual void setTargets(const std::string &path);

			virtual const std::vector<std::string> &getTargets() const;

			virtual const std::string &getTargetConfigPath() const;

			virtual void setTargetConfigPath(const std::string &path);
	};
}
