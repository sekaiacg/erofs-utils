#include "ErofsHardlinkHandle.h"

namespace skkk {

	ErofsHardlinkEntry::ErofsHardlinkEntry(erofs_nid_t _nid, const char *_path) {
		this->nid = _nid;
		this->path = _path;
	}

	int erofsHardlinkInsert(erofs_nid_t nid, const char *path) {
		if (!path) return -ENOENT;
		erofsHardlinkMap[nid % NR_HARDLINK_HASHTABLE] = {nid, path};
		return 0;
	}

	const char *erofsHardlinkFind(erofs_nid_t nid) {
		auto it = erofsHardlinkMap.find(nid % NR_HARDLINK_HASHTABLE);
		if (it != erofsHardlinkMap.end()) {
			if (it->second.nid == nid) {
				return it->second.path.c_str();
			}
		}
		return nullptr;
	}

	void erofsHardlinkExit() {
		erofsHardlinkMap.clear();
	}
}
