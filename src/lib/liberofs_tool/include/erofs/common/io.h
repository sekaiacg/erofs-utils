#pragma once

#include "config.h"

#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <vector>

#include "ioDefs.h"

namespace skkk::erofs {
	int openFileRD(const std::string &path);

	int openFileRW(const std::string &path);

	void closeFd(int &fd);

	int blobRead(int fd, void *data, uint64_t offset, uint64_t length);

	bool readToString(const std::string &filePath, std::string &result);

	bool readAllLines(const std::string &filePath, std::vector<std::string> &result);
}
