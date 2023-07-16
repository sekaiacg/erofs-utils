#ifndef EXTRACT_EROFS_HARDLINK_HANDLE_H
#define EXTRACT_EROFS_HARDLINK_HANDLE_H

#include <mutex>
#include <string>
#include <unordered_map>

using namespace std;

#define NR_HARDLINK_HASHTABLE    16384

static mutex erofsHardlinkLock;

namespace skkk {

	class ErofsHardlinkEntry {
		public:
			uint64_t nid = 0;
			string path;
		public:
			ErofsHardlinkEntry() = default;

			ErofsHardlinkEntry(uint64_t _nid, const char *_path);

	};

	inline static unordered_map<uint64_t, ErofsHardlinkEntry> erofsHardlinkMap;

	int erofsHardlinkInsert(uint64_t nid, const char *path);

	const char *erofsHardlinkFind(uint64_t nid);

	void erofsHardlinkExit();

}

#endif // EXTRACT_EROFS_HARDLINK_HANDLE_H
