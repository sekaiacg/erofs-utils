#include <algorithm>

#include "ExtractOperation.h"
#include "ExtractState.h"
#include "ExtractHelper.h"
#include "Logging.h"
#include "Utils.h"
#include "threadpool.h"

namespace skkk {

	void ExtractOperation::setImgPath(const char *path) {
		imgPath = path;
		strTrim(imgPath);
		LOGCD("config: imagePath=%s", imgPath.c_str());
		imgBaseName = path;
		if (!imgPath.empty()) {
			auto ps = imgPath.rfind('/');
			if (ps != string::npos)
				imgBaseName = imgPath.substr(ps + 1, imgPath.size());
			ps = imgBaseName.find('.');
			if (ps != string::npos) imgBaseName.erase(ps, imgBaseName.size());
			LOGCD("config: imgBaseName=%s", imgBaseName.c_str());
		}
	}

	void ExtractOperation::erofsOperationExit() {
		for_each(erofsNodes.begin(), erofsNodes.end(),
				 [](auto *eNode) { delete eNode; });
		erofsNodes.clear();
		nodeDirs.clear();
		nodeOther.clear();
	}

	const string &ExtractOperation::getImgPath() const { return imgPath; }

	const string &ExtractOperation::getImgBaseName() const { return imgBaseName; }

	void ExtractOperation::setOutDir(const char *path) { outDir = path; }

	int ExtractOperation::initOutDir() {
		int rc = RET_EXTRACT_DONE;
		strTrim(outDir);

		if (outDir.empty()) {
			configDir = "./config";
			outDir = "./" + imgBaseName;
		} else {
			const char *oDir = outDir.c_str();
			auto oSize = outDir.size();
			// check dir is root: "/","//","///",...
			bool isRoot = true;
			for (int i = 0; i < oSize; i++) {
				isRoot = oDir[i] == '/';
			}
			if (isRoot) {
				LOGCE("Not allow extracting to root: '%s'", outDir.c_str());
				rc = RET_EXTRACT_OUTDIR_ROOT;
			} else {
				configDir = outDir + "/config";
				outDir = outDir + "/" + imgBaseName;
			}
		}
		return rc;
	}

	int ExtractOperation::createExtractOutDir() const {
		int rc = RET_EXTRACT_DONE, err;
		if (!dirExists(outDir)) {
			err = mkdirs(outDir.c_str(), 0700);
			if (err) {
				rc = RET_EXTRACT_CREATE_DIR_FAIL;
				LOGCE("create out dir fail: '%s'", outDir.c_str());
			}
		}
		return rc;
	}

	int ExtractOperation::createExtractConfigDir() const {
		int rc = RET_EXTRACT_DONE, err;
		if (!dirExists(configDir)) {
			err = mkdirs(configDir.c_str(), 0700);
			if (err) {
				rc = RET_EXTRACT_CREATE_DIR_FAIL;
				LOGCE("create config dir fail: '%s'", configDir.c_str());
			}
		}
		return rc;
	}

	const string &ExtractOperation::getOutDir() const { return outDir; }

	const string &ExtractOperation::getConfDir() const { return configDir; }

	int ExtractOperation::initAllErofsNode() const { return initErofsNodeByRoot(); }

	int ExtractOperation::initErofsNodeByTarget() const { return initErofsNodeByTargetPath(targetPath); }

	int ExtractOperation::initErofsNodeAuto() const {
		return targetPath.empty() ?
			   initErofsNodeByRoot() : initErofsNodeByTargetPath(targetPath);
	}

	const ErofsNode
	*ExtractOperation::createErofsNode(const char *path, short typeId, struct erofs_inode *inode) {
		auto *eNode = new ErofsNode{path, typeId, inode};
		erofsNodes.push_back(eNode);
		initSecurityContext(eNode, inode);
		return eNode;
	}

	void ExtractOperation::initDirAndOther() {
		for_each(erofsNodes.begin(), erofsNodes.end(), [](auto &eNode) {
			if (eNode->getTypeId() == EROFS_FT_DIR) {
				nodeDirs.push_back(eNode);
			} else {
				nodeOther.push_back(eNode);
			}
		});
		LOGCD("initDirAndOther done");
	}

	void ExtractOperation::addErofsNode(ErofsNode *eNode) { erofsNodes.push_back(eNode); }

	const vector<ErofsNode *> &ExtractOperation::getErofsNodes() { return erofsNodes; }

	static inline void printFsConfWithColor(const ErofsNode *eNode) {
		LOGCI("type=%s dataLayout=%s fsConfig=[%s] seLabel=[%s]",
			  eNode->getTypeIdCStr(),
			  eNode->getDataLayoutCStr(),
			  eNode->getFsConfig().c_str(),
			  eNode->getSeLabel().c_str()
		);
	}

	static inline void printFsConf(const ErofsNode *eNode) {
		LOGI("type=%s dataLayout=%s fsConfig=[%s] seLabel=[%s]",
			 eNode->getTypeIdCStr(),
			 eNode->getDataLayoutCStr(),
			 eNode->getFsConfig().c_str(),
			 eNode->getSeLabel().c_str()
		);
	}

	void ExtractOperation::printInitializedNode() {
		for_each(erofsNodes.begin(), erofsNodes.end(), printFsConf);
	}

	void ExtractOperation::extractFsConfigAndSeLabel() const {
		string fsConfigPath = configDir + "/" + imgBaseName + "_fs_config";
		string fsSeContextPath = configDir + "/" + imgBaseName + "_file_contexts";
		FILE *fsConfigFile = fopen(fsConfigPath.c_str(), "wb");
		FILE *seContextFile = fopen(fsSeContextPath.c_str(), "wb");
		const char *_imgBaseName = imgBaseName.c_str();
		LOGCI(BROWN "fs_config|file_contexts" LOG_RESET_COLOR "  " GREEN2_BOLD "saving..." LOG_RESET_COLOR);
		if (fsConfigFile && seContextFile) {
			for_each(erofsNodes.begin(), erofsNodes.end(),
					 [&fsConfigFile, &seContextFile, &_imgBaseName](auto *eNode) {
						 eNode->writeFsConfigAndSeContext2File(fsConfigFile, seContextFile, _imgBaseName);
					 });
			LOGCI(BROWN "fs_config|files_context" LOG_RESET_COLOR "  " GREEN2_BOLD "done." LOG_RESET_COLOR);
		} else
			LOGCE(BROWN "fs_config|files_context" LOG_RESET_COLOR "  " RED2_BOLD "fail!" LOG_RESET_COLOR);
		if (fsConfigFile) fclose(fsConfigFile);
		if (seContextFile) fclose(seContextFile);
	}

	void ExtractOperation::writeExceptionInfo2File() const {
		if (exceptionSize > 0) {
			FILE *infoFile = fopen((configDir + "/exception.log").c_str(), "w");
			for (const auto &eNode: erofsNodes) {
				eNode->writeExceptionInfo2FileIfExists(infoFile);
			}
			LOGCE(RED2 "An exception occurred while fetching, the info has been saved!" COLOR_NONE);
		}
	}

	static inline void extractNodeTask(ErofsNode *eNode, const string &outdir) {
		if (eNode->initExceptionInfo(eNode->writeNodeEntity2File(outdir)))
			ExtractOperation::exceptionSize++;
	}

	static inline void extractNodeTaskMultiThread(ErofsNode *eNode, const string &outdir) {
		if (eNode->initExceptionInfo(eNode->writeNodeEntity2File(outdir)))
			ExtractOperation::exceptionSize++;
		ExtractOperation::extractTaskRunCount++;
	}

	static inline void printExtractProgress(int totalSize, int index, int perPrint, bool hasEnter) {
		if (index % perPrint == 0 || index == totalSize) {
			float p = (float) index / (float) totalSize * 100.0f;
			printf(BROWN2_BOLD "Extract: " COLOR_NONE
				   GREEN2_BOLD "[ " COLOR_NONE RED2   "%.2f%%" LOG_RESET_COLOR GREEN2_BOLD " ]" COLOR_NONE
				   "\r",
				   p
			);
			fflush(stdout);
			if (hasEnter && p == 100) [[unlikely]] {
				printf("\n");
			}
		}
	}

	void ExtractOperation::extractNodeDirs() const {
		ExtractOperation::initDirAndOther();
		if (!nodeDirs.empty()) {
			for (const auto &eNode: nodeDirs) {
				extractNodeTask(eNode, outDir);
			}
		}
	}

	void ExtractOperation::extractErofsNode() const {
		extractNodeDirs();
		if (!nodeOther.empty()) {
			int nodeOtherSize = nodeOther.size();
			for (int i = 0; i < nodeOtherSize; i++) {
				extractNodeTask(nodeOther[i], outDir);
				printExtractProgress(nodeOtherSize, i + 1, 4, true);
			}
		}
		// If there is an exception
		writeExceptionInfo2File();
	}

	void ExtractOperation::extractErofsNodeMultiThread() const {
		extractNodeDirs();
		LOGCI(GREEN2_BOLD "Use " COLOR_NONE RED2 "%d" COLOR_NONE GREEN2_BOLD " therads" COLOR_NONE, threadNum);

		int nodeOtherSize = nodeOther.size();
		threadpool tp(threadNum);
		for (const auto &eNode: nodeOther) {
			tp.commit(extractNodeTaskMultiThread, eNode, outDir);
		}

		int i = 0;
		while (extractTaskRunCount < nodeOtherSize) {
			if (i != extractTaskRunCount) {
				printExtractProgress(nodeOtherSize, extractTaskRunCount, 2, false);
				i = extractTaskRunCount;
			}
			sleep(0);
		}
		printExtractProgress(1, 1, 1, true);
		LOGCD("extractTaskRunCount=%d nodeFilesSize=%d", i, nodeOtherSize, nodeOther.size());

		writeExceptionInfo2File();
	}
}
