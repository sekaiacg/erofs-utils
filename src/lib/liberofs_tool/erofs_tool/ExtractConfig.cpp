#include <string>

#include "LogBase.h"
#include "Utils.h"
#include "erofs/ExtractConfig.h"

namespace skkk::erofs {
	const std::string &ExtractConfig::getImagePath() const {
		return imagePath;
	}

	void ExtractConfig::setImagePath(const std::string &path) {
		strTrim(imagePath = path);
		handleWinPath(imagePath);
	}

	const std::string &ExtractConfig::getImageBaseName() const {
		return imageBaseName;
	}

	uint64_t ExtractConfig::getOffset() const {
		return offset;
	}

	void ExtractConfig::setOffset(uint64_t offset) {
		this->offset = offset;
	}

	const std::string &ExtractConfig::getOutDir() const {
		return outDir;
	}

	void ExtractConfig::setOutDir(const std::string &path) {
		strTrim(outDir = path);
		handleWinPath(outDir);

		imageBaseName = path;
		if (!imagePath.empty()) {
			auto ps = imagePath.rfind('/');
			if (ps != std::string::npos)
				imageBaseName = imagePath.substr(ps + 1, imagePath.size());
			ps = imageBaseName.find('.');
			if (ps != std::string::npos) imageBaseName.erase(ps, imageBaseName.size());
			LOGCD("config: imgBaseName={}", imageBaseName.c_str());
		}
	}

	std::string ExtractConfig::getConfigDir() const {
		return configDir;
	}

	void ExtractConfig::setTargets(const std::string &path) {
		strTrim(targetPath = path);
		handleWinPath(targetPath);
		splitString(targets, targetPath, ",", true);
	}

	const std::vector<std::string> &ExtractConfig::getTargets() const {
		return targets;
	}

	const std::string &ExtractConfig::getTargetConfigPath() const {
		return targetConfigPath;
	}

	void ExtractConfig::setTargetConfigPath(const std::string &path) {
		strTrim(this->targetConfigPath = path);
		handleWinPath(targetConfigPath);
	}
}
