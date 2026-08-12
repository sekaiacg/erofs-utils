#pragma once

#include <atomic>
#include <memory>
#include <mutex>

#include "erofs/ErofsInfo.h"
#include "erofs/ErofsWriter.h"
#include "erofs/ExtractConfig.h"

namespace skkk::erofs {
	class ErofsParser {
		std::mutex _mutex;
		std::atomic_bool initialized = false;
		std::shared_ptr<ErofsInfo> erofsInfo;
		std::shared_ptr<ErofsWriter> erofsWriter;

		public:
			ErofsParser() = default;

			ErofsParser(const ErofsParser &other) = delete;

			ErofsParser(ErofsParser &&other) = delete;

			ErofsParser &operator=(const ErofsParser &other) = delete;

			ErofsParser &operator=(ErofsParser &&other) = delete;

			bool parse(const ExtractConfig &config);

			std::shared_ptr<ErofsInfo> getErofsInfo();

			std::shared_ptr<ErofsWriter> getErofsWriter();
	};
}
