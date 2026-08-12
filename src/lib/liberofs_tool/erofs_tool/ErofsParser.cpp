#include "erofs/ErofsParser.h"

namespace skkk::erofs {
	bool ErofsParser::parse(const ExtractConfig &config) {
		std::lock_guard lock(_mutex);
		if (!initialized) {
			std::shared_ptr<ErofsInfo> info = std::make_shared<ErofsInfo>(config);
			if (info && info->initErofsInfo()) {
				erofsInfo = info;
				erofsWriter = std::make_shared<ErofsWriter>(erofsInfo);
			}
			return initialized = (erofsInfo && erofsWriter);
		}
		return false;
	}

	std::shared_ptr<ErofsInfo> ErofsParser::getErofsInfo() {
		std::lock_guard lock(_mutex);
		return initialized ? erofsInfo : nullptr;
	}

	std::shared_ptr<ErofsWriter> ErofsParser::getErofsWriter() {
		std::lock_guard lock(_mutex);
		return initialized ? erofsWriter : nullptr;
	}
}
