#include "erofs/ErofsHardlinkHandle.h"

namespace skkk::erofs {
	ErofsHardlinkEntry::ErofsHardlinkEntry(uint64_t nid, const char *path) {
		this->nid = nid;
		this->path = path;
	}

	int ErofsHardlinkEntry::erofsHardlinkInsert(uint64_t nid, const char *path) {
		if (!path) return -ENOENT;
		erofsHardlinkMap[nid % NR_HARDLINK_HASHTABLE] = {nid, path};
		return 0;
	}

	const char *ErofsHardlinkEntry::erofsHardlinkFind(uint64_t nid) {
		auto it = erofsHardlinkMap.find(nid % NR_HARDLINK_HASHTABLE);
		if (it != erofsHardlinkMap.end()) {
			if (it->second.nid == nid) {
				return it->second.path.c_str();
			}
		}
		return nullptr;
	}

	void ErofsHardlinkEntry::erofsHardlinkExit() {
		erofsHardlinkMap.clear();
	}
}
