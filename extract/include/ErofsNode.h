#ifndef EXTRACT_EROFS_NODE_H
#define EXTRACT_EROFS_NODE_H

#include <string>
#include <erofs/internal.h>
#include <set>

#include "Utils.h"

using namespace std;

namespace skkk {

	static inline void handleSpecialSymbols(string &str) {
		strReplaceAll(str, ".", "\\.");
		strReplaceAll(str, "+", "\\+");
		strReplaceAll(str, "[", "\\[");
		strReplaceAll(str, "]", "\\]");
	}

	static set<string> otherPathsInRootDir = {
			"/lost+found"
	};

	/**
	 * erofs node
	 */
	class ErofsNode {
		private:
			string path;
			short typeId = EROFS_FT_UNKNOWN;
			erofs_inode *inode = nullptr;
			string fsConfig;
			string selinuxLabel;
			erofs_nid_t nid;
			umode_t i_mode;
			u32 i_uid;
			u32 i_gid;
			uint64_t i_mtime;
			u32 i_mtime_nsec;
			unsigned char dataLayout;
			uint64_t capabilities = 0;
			string extractExceptionInfo;

		public:
			ErofsNode(const char *path, short typeId, erofs_inode *inode);

			~ErofsNode();

			const string &getPath() const;

			short getTypeId() const;

			erofs_inode *getErofsInode() const;

			const char *getTypeIdCStr() const;

			const char *getDataLayoutCStr() const;

			const string &getFsConfig() const;

			const string &getSelinuxLabel() const;

			void setSelinuxLabel(const string &label);

			uint64_t getCapability() const;

			void setCapability(uint64_t _capabilities);

			void setFsConfigCapabilities(const char *capabilitiesStr);

			bool initExceptionInfo(int err);

			void writeFsConfig2File(FILE *fsConfigFile, const char *mountPoint) const;

			void writeSelinuxLabel2File(FILE *selinuxLabelsFile, const char *mountPoint) const;

			int writeNodeEntity2File(const string &outDir);

			void writeExceptionInfo2FileIfExists(FILE *infoFile) const;

	};
}
#endif //EXTRACT_EROFS_NODE_H
