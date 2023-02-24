#ifndef EXTRACT_EROFS_NODE_H
#define EXTRACT_EROFS_NODE_H

#include <string>
#include <erofs/internal.h>

#include "Utils.h"

using namespace std;

namespace skkk {

	static inline string handleSpecialSymbols(const string &str) {
		string tmp = string(str);
		strReplaceAll(tmp, ".", "\\.");
		strReplaceAll(tmp, "+", "\\+");
		strReplaceAll(tmp, "[", "\\[");
		strReplaceAll(tmp, "]", "\\]");
		return tmp;
	}

	/**
	 * erofs node
	 */
	class ErofsNode {
		private:
			string path;
			short typeId = EROFS_FT_UNKNOWN;
			erofs_inode *inode = nullptr;
			string fsConfig;
			string seContext;
			erofs_nid_t nid;
			umode_t i_mode;
			u32 i_uid;
			u32 i_gid;
			uint64_t i_mtime;
			u32 i_mtime_nsec;
			unsigned char dataLayout;
#ifdef WITH_ANDROID
			uint64_t capabilities = 0;
#endif
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

			const string &getSeLabel() const;

			void setSeContext(const string &_seContext);

#ifdef WITH_ANDROID

			uint64_t getCapability() const;

			void setCapability(uint64_t _capabilities);

			void setFsConfigCapabilities(const char *capabilitiesStr);

#endif

			bool initExceptionInfo(int err);

			void writeFsConfigAndSeContext2File(FILE *fsConfigFile, FILE *seContextFile, const char *imgBaseName) const;

			int writeNodeEntity2File(const string &outDir);

			void writeExceptionInfo2FileIfExists(FILE *infoFile) const;

	};
}
#endif //EXTRACT_EROFS_NODE_H
