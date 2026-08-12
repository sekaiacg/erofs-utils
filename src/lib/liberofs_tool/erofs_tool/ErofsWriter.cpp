#include <fstream>
#include <future>
#include <ranges>

#include "LogBase.h"
#include "LogProgress.h"
#include "erofs/common/io.h"
#include "erofs/common/threadpool.h"
#include "erofs/ErofsWriter.h"
#include "erofs/ErofsNodeHelper.h"

namespace skkk::erofs {
	ErofsWriter::ErofsWriter(const std::shared_ptr<ErofsInfo> &erofsInfo)
		: erofsInfo(erofsInfo),
		  config(erofsInfo->getConfig()) {
		nodes.reserve(NODE_INIT_SIZE);
		dirNodes.reserve(NODE_INIT_SIZE);
		otherNodes.reserve(NODE_INIT_SIZE);
	}

	const std::vector<ErofsNode> &ErofsWriter::getNodes() {
		return nodes;
	}

	std::vector<ErofsNode *> &ErofsWriter::getDirNodes() {
		return dirNodes;
	}

	std::vector<ErofsNode *> &ErofsWriter::getOtherNodes() {
		return otherNodes;
	}

	void ErofsWriter::clearNodes() {
		nodes.clear();
		dirNodes.clear();
		otherNodes.clear();
		erofsHardlinkEntry.erofsHardlinkExit();
	}

	bool ErofsWriter::initErofsNodeByTarget() {
		auto &sbi = erofsInfo->getErofsSbi();
		if (config.isExtractTargetConfig) {
			const auto &path = config.getTargetConfigPath();
			std::vector<std::string> targets;
			targets.reserve(32);
			if (readAllLines(path, targets)) {
				return ErofsNodeHelper::initErofsNodeByTargets(sbi, nodes, targets,
				                                               config.targetRecursive);
			}
			LOGCE("target config '{}' does not exist! ", path);
		}
		return ErofsNodeHelper::initErofsNodeByTargets(sbi, nodes, config.getTargets(), config.targetRecursive);
	}

	bool ErofsWriter::initErofsNode() {
		return ErofsNodeHelper::initErofsNodeByRoot(nodes, erofsInfo->getErofsSbi());
	}

	bool ErofsWriter::initErofsNodeConfig() {
		for (const auto &node: nodes) {
		}

		return false;
	}

	static void printFsConf(const ErofsNode &node) {
		LOGI("type={:7} dataLayout={:19} {} {}",
		     node.getTypeCStr(),
		     node.getDataLayout(),
		     node.getFsConfig(),
		     node.getSelinuxLabel()
		);
	}

	void ErofsWriter::printInitializedNode() {
		std::ranges::for_each(nodes, printFsConf);
	}

	void ErofsWriter::writeFsConfigAndSelinuxLabel() const {
		std::string configPath = config.getConfigDir() + "/" + config.getImageBaseName();
		std::string fsConfigPath = configPath + "_fs_config";
		std::string selinuxLabelsPath = configPath + "_file_contexts";
		std::ofstream fsConfigFile{fsConfigPath, std::ios::binary | std::ios::trunc};
		std::ofstream selinuxLabelsFile{selinuxLabelsPath, std::ios::binary | std::ios::trunc};
		LOGCI(BROWN("fs_config|file_contexts|fs_options" "  " GREEN2_BOLD("saving...")));
		if (fsConfigFile.is_open() && selinuxLabelsFile.is_open()) {
			bool isRoot = true;
			for (const auto &node: nodes) {
				fsConfigFile << node.getFsConfig() << "\n";
				auto &seLabel = node.getSelinuxLabelConfig();
				if (!seLabel.empty()) {
					selinuxLabelsFile << seLabel << "\n";
				}
				if (isRoot && node.getPath() == "/") [[unlikely]] {
					isRoot = false;
					for (auto &otherPath: otherPathsInRootDir) {
						std::string fsConfig = std::format("{} {} {} {:04o}",
						                                   otherPath,
						                                   node.getUid(),
						                                   node.getGid(),
						                                   node.getMode() & 0777);
						std::string selinuxLabel = otherPath + " " + node.getSelinuxLabel();
						handleSpecialSymbols(selinuxLabel);
						fsConfigFile << fsConfig << "\n";
						selinuxLabelsFile << selinuxLabel << "\n";
					}
				}
			}
			if (!config.isExtractTarget && !config.isExtractTargetConfig) {
				std::ofstream mkfsOptionFile{configPath + "_mkfs_options", std::ios::binary | std::ios::trunc};
				if (mkfsOptionFile.is_open()) {
					auto time = erofsInfo->getBuildTime();
					std::string timeStr = ctime(&time);
					const std::string uuid = erofsInfo->getUuid();
					strTrim(timeStr);
					bool isBigPcluster = erofsInfo->isFeatureIncompat(EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER);
					mkfsOptionFile << std::format("Filesystem created:    {}\n", timeStr);
					mkfsOptionFile << std::format("Filesystem UUID:       {}\n", uuid);
					// @formatter:off
					mkfsOptionFile << std::format("mkfs.erofs options:    "
						"-zlz4hc " // default: lz4hc
						"{}"
					 	"-T {} -U {} "
					 	"--fs-config-file={} "
					 	"--file-contexts={} "
					 	"{} " // output image file
					 	"{}\n", // input dir
					 	isBigPcluster ? "-C 16384 " : "", // default 16K
					 	time, uuid,
					 	fsConfigPath, selinuxLabelsPath,
					 	config.getImageBaseName() + "_repack.img",
					 	config.getOutDir());
					// @formatter:on
				}
			}
			LOGCI(BROWN("fs_config|file_contexts|mkfs_options" "  " GREEN2_BOLD("done.")));
		} else
			LOGCE(BROWN("fs_config|file_contexts|mkfs_options" "  " RED2_BOLD("fail!")));
	}

	void ErofsWriter::writeExceptionInfo2File() const {
		if (exceptionSize > 0) {
			std::ofstream infoFile{config.getConfigDir() + "/exception.log", std::ios::binary | std::ios::trunc};
			if (infoFile.is_open()) {
				for (const auto &node: nodes) {
					node.writeExceptionInfo2FileIfExists(infoFile);
				}
				LOGCE(RED2("An exception occurred while fetching, the info has been saved!"));
			}
		}
	}

	static void extractTask(const ExtractConfig &config, ErofsNode &node, ErofsHardlinkEntry &erofsHardlinkEntry,
	                        std::atomic_int &extractProgress, std::atomic_int &exceptionSize) {
		if (node.initExceptionInfo(node.write2File(config, erofsHardlinkEntry))) {
			++exceptionSize;
		}
		++extractProgress;
	}

	void ErofsWriter::extractDirs() {
		ErofsNodeHelper::erofsNodeClassification(nodes, dirNodes, otherNodes, erofsHardlinkEntry);
		for (const auto &node: dirNodes) {
			extractTask(config, *node, erofsHardlinkEntry, extractProgress, exceptionSize);
		}
	}

#define PRINT_PROGRESS_FMT \
	BROWN2_BOLD("Extract: ") \
	GREEN2_BOLD("[ ") RED2("%.2f%%") GREEN2_BOLD(" ]") \
	"\r"

	static void printProgressMT(bool isSilent, uint64_t totalSize, const std::atomic_int &progress, bool hasEnter) {
		if (!isSilent) {
			progressMT(PRINT_PROGRESS_FMT, totalSize, progress, hasEnter);
		}
	}

	void ErofsWriter::extract() {
		std::future<void> progressThread;
		progressThread = std::async(std::launch::async, printProgressMT, false, nodes.size(),
		                            std::ref(extractProgress), true);
		extractDirs();
		for (const auto &node: otherNodes) {
			extractTask(config, *node, erofsHardlinkEntry, extractProgress, exceptionSize);
		}
		if (progressThread.valid()) progressThread.wait();
		writeExceptionInfo2File();
	}

	void ErofsWriter::extractByMT() {
		LOGCI(GREEN2_BOLD("Using ") RED2 ("{}") GREEN2_BOLD (" threads"), config.threadNum);
		std::future<void> progressThread;
		progressThread = std::async(std::launch::async, printProgressMT, false, nodes.size(),
		                            std::ref(extractProgress), true);
		extractDirs();
		std::threadpool tp(config.threadNum);
		for (const auto &node: otherNodes) {
			tp.commit(extractTask, std::ref(config), std::ref(*node), std::ref(erofsHardlinkEntry),
			          std::ref(extractProgress), std::ref(exceptionSize));
		}
		if (progressThread.valid()) progressThread.wait();
		writeExceptionInfo2File();
	}
}
