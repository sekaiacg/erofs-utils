#include "ExtractOperation.h"
#include "LogBase.h"
#include "Utils.h"
#include "erofs/ErofsNodeHelper.h"

namespace skkk::erofs {
	int ExtractOperation::initOutDir() {
		if (outDir.empty()) {
			outDir = "./" + imageBaseName;
			configDir = "./config";
		} else {
			if (outDir.size() > 1 &&
			    (outDir.at(outDir.size() - 1) == '/' ||
			     outDir.at(outDir.size() - 1) == '\\'))
				outDir.pop_back();
			if (outDir.size() >= PATH_MAX) {
				LOGE("outDir directory name too long!");
				return RET_EXTRACT_OUTDIR_ROOT;
			}
#if !(defined(_WIN32) || defined(__CYGWIN__))
			const char *oDir = outDir.c_str();
			auto oSize = outDir.size();
			// check dir is root: "/","//","///",...
			bool isRoot = true;
			for (int i = 0; i < oSize; i++) {
				isRoot = oDir[i] == '/';
			}
			if (isRoot) {
				LOGCE("Not allow extracting to root: '{}'", outDir);
				return RET_EXTRACT_OUTDIR_ROOT;
			}
#endif
			configDir = outDir + "/config";
			outDir = outDir + "/" + imageBaseName;
		}
		return RET_EXTRACT_DONE;
	}

	int ExtractOperation::createDir(const std::string &tag, const std::string &path) {
		int rc = RET_EXTRACT_DONE;
		if (!dirExists(path)) {
			if (mkdirs(path.c_str(), 0755)) {
				rc = RET_EXTRACT_CREATE_DIR_FAIL;
				LOGCE("create {} dir fail: '{}'({})", tag, path, strerror(errno));
			}
		}
		return rc;
	}

	int ExtractOperation::createExtractConfigDir() const {
		return createDir("config", configDir);
	}

	int ExtractOperation::createExtractOutDir() const {
		return createDir("out", outDir);
	}
}
