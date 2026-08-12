#pragma once

#include <erofs/ExtractConfig.h>

namespace skkk::erofs {
	class ExtractOperation : public ExtractConfig {
		public:
			ExtractOperation() = default;

			int initOutDir();

			static int createDir(const std::string &tag, const std::string &path);

			int createExtractConfigDir() const;

			int createExtractOutDir() const;

			void extract() const;
	};
};
