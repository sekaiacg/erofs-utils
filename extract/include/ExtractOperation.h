#ifndef EXTRACT_OPERATION_H
#define EXTRACT_OPERATION_H

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <sys/stat.h>
#include <vector>
#include <erofs/internal.h>

#include "ErofsNode.h"

using namespace std;

namespace skkk {

	/**
	 * extract operation and config
	 */
	class ExtractOperation {
		private:
			/* instance */
			static inline ExtractOperation *instance = nullptr;
			/* erofs node list */
			static inline vector<ErofsNode *> erofsNodes;
			/* there are only dir type nodes */
			static inline vector<ErofsNode *> nodeDirs;
			/* there are only other type nodes */
			static inline vector<ErofsNode *> nodeOther;

			string imgPath;
			string imgBaseName;
			string outDir;
			string configDir;

		private:
			ExtractOperation() = default;

			~ExtractOperation() = default;

			ExtractOperation(ExtractOperation const &);

			ExtractOperation &operator=(ExtractOperation const &);

		public:
			char *iter_path = nullptr;
			size_t iter_pos = 0;
			static inline atomic_int extractTaskRunCount = 0;
			static inline atomic_int exceptionSize = 0;
			mode_t umask = ::umask(0);
			bool superuser = geteuid() == 0;
			bool preserve_owner = superuser;
			bool preserve_perms = superuser;
			bool isPrintAllNode = false;
			bool isPrintTarget = false;
			bool check_decomp = false;
			bool isExtractAllNode = false;
			bool isExtractTarget = false;
			bool useMultiThread = false;
			unsigned int threadNum = 0;
			unsigned int hardwareConcurrency = thread::hardware_concurrency();
			unsigned int limitHardwareConcurrency = hardwareConcurrency * 2;
			bool overwrite = false;
			string targetPath;
			string targetConfPath;
			bool extractOnlyConfAndSeLabel = false;

		public:

			static inline ExtractOperation *getInstance() {
				if (!instance) {
					instance = new ExtractOperation();
				}
				return instance;
			}

			static void erofsOperationExit();

			void setImgPath(const char *path);

			const string &getImgPath() const;

			const string &getImgBaseName() const;

			void setOutDir(const char *path);

			int initOutDir();

			int createExtractOutDir() const;

			int createExtractConfigDir() const;

			const string &getOutDir() const;

			const string &getConfDir() const;

			int initAllErofsNode() const;

			int initErofsNodeByTarget() const;

			int initErofsNodeAuto() const;

			/**
			 * new ErofsNode(const char *path, short typeId, struct erofs_inode *inode)
			 *
			 * @param path
			 * @param typeId
			 * @param inode
			 */
			static const ErofsNode *createErofsNode(const char *path, short typeId, struct erofs_inode *inode);

			static void initDirAndOther();

			static void addErofsNode(ErofsNode *eNode);

			static const vector<ErofsNode *> &getErofsNodes();

			/**
			 * print all extract entity
			 * "Extract: type=DIR dataLayout= / 0 0 0644 capabilities=0x0"
			 */
			static void printInitializedNode() ;

			void extractFsConfigAndSeLabel() const;

			void writeExceptionInfo2File() const;

			void extractNodeDirs() const;

			void extractErofsNode() const;

			void extractErofsNodeMultiThread() const;
	};

	/**
	 * Global instance
	 */
	static ExtractOperation *eo = ExtractOperation::getInstance();
}
#endif // end EXTRACT_OPERATION_H
