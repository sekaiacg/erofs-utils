#pragma once

#include <atomic>
#include <memory>
#include <vector>

#include "erofs/ErofsInfo.h"
#include "erofs/ErofsNode.h"
#include "erofs/ErofsHardlinkHandle.h"

namespace skkk::erofs {
	class ErofsWriter {
		const std::shared_ptr<ErofsInfo> &erofsInfo;
		const ExtractConfig &config;
		constexpr static uint32_t NODE_INIT_SIZE = 4096;
		std::vector<ErofsNode> nodes;
		std::vector<ErofsNode *> dirNodes;
		std::vector<ErofsNode *> otherNodes;
		ErofsHardlinkEntry erofsHardlinkEntry;

		std::atomic_int extractProgress = 0;
		std::atomic_int exceptionSize = 0;
		std::vector<std::string> extractExceptionInfos;

		public:
			explicit ErofsWriter(const std::shared_ptr<ErofsInfo> &erofsInfo);

			virtual ~ErofsWriter() = default;

			const std::vector<ErofsNode> &getNodes();

			std::vector<ErofsNode *> &getDirNodes();

			std::vector<ErofsNode *> &getOtherNodes();

			void clearNodes();

			virtual bool initErofsNodeByTarget();

			virtual bool initErofsNode();

			virtual bool initErofsNodeConfig();

			virtual void printInitializedNode();

			virtual void writeFsConfigAndSelinuxLabel() const;

			void writeExceptionInfo2File() const;

			void extractDirs();

			void extract();

			void extractByMT();
	};
}
