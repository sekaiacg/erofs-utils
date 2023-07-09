#ifndef EXTRACT_EROFS_HARDLINK_HANDLE_H
#define EXTRACT_EROFS_HARDLINK_HANDLE_H

#include <mutex>
#include <string>
#include <unordered_map>
#include <erofs/internal.h>

using namespace std;

#define NR_HARDLINK_HASHTABLE    16384

static mutex erofsHardlinkLock;

namespace skkk {

	class ErofsHardlinkEntry {
		public:
			erofs_nid_t nid = 0;
			string path;
		public:
			ErofsHardlinkEntry() = default;

			ErofsHardlinkEntry(erofs_nid_t _nid, const char *_path);

	};

	inline static unordered_map<uint64_t, ErofsHardlinkEntry> erofsHardlinkMap;

	int erofsHardlinkInsert(erofs_nid_t nid, const char *path);

	const char *erofsHardlinkFind(erofs_nid_t nid);

	void erofsHardlinkExit();

}

#endif // EXTRACT_EROFS_HARDLINK_HANDLE_H
