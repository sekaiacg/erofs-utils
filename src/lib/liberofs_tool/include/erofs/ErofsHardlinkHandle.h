#pragma once

#include <cinttypes>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#define NR_HARDLINK_HASHTABLE    16384

namespace skkk::erofs {
	class ErofsHardlinkEntry {
		public:
			std::unique_ptr<std::mutex> erofsHardlinkLock = std::make_unique<std::mutex>();
			uint64_t nid = 0;
			std::string path;
			std::unordered_map<uint64_t, ErofsHardlinkEntry> erofsHardlinkMap;

		public:
			ErofsHardlinkEntry() = default;

			ErofsHardlinkEntry(uint64_t _nid, const char *_path);

			int erofsHardlinkInsert(uint64_t nid1, const char *path);

			const char *erofsHardlinkFind(uint64_t nid);

			void erofsHardlinkExit();
	};
}
