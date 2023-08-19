#ifndef EXTRACT_UTILS_H
#define EXTRACT_UTILS_H

#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <iconv.h>

using namespace std;

static inline bool dirExists(const string &dirPath) {
	struct stat st = {};

	if (stat(dirPath.c_str(), &st) == 0) {
		return S_ISDIR(st.st_mode);
	}
	return false;
}

static inline bool fileExists(const string &filePath) {
	struct stat st = {};

	if (stat(filePath.c_str(), &st) == 0) {
		return S_ISREG(st.st_mode);
	}
	return false;
}

static inline int mkdirs(const char *dirPath, mode_t mode) {
	int len, err = 0;
	char str[PATH_MAX + 1] = {0};
	strncpy(str, dirPath, PATH_MAX);
	len = strlen(str);
	for (int i = 0; i < len; i++) {
#if !(defined(_WIN32) || defined(__CYGWIN__))
		if (str[i] == '/' && i > 0) {
#else
		if (str[i] == '/' && i > 0 && str[i - 1] != ':') {
#endif
			str[i] = '\0';
			if (access(str, F_OK) != 0) {
				err = mkdir(str, mode);
				if (err) return err;
			}
			str[i] = '/';
		}
	}
	if (len > 0 && access(str, F_OK) != 0) {
		err = mkdir(str, mode);
	}
	return err;
}

static inline void strTrim(string &str) {
	if (!str.empty()) {
		str.erase(0, str.find_first_not_of(" \n\r\t\v\f"));
		str.erase(str.find_last_not_of(" \n\r\t\v\f") + 1);
	}
}

static inline void strReplaceAll(string &str, const string &oldValue, const string &newValue) {
	auto oldValueSize = oldValue.size();
	auto newValueSize = newValue.size();
	auto pos = str.find(oldValue);
	while (pos != string::npos) {
		str.replace(pos, oldValueSize, newValue);
		pos = str.find(oldValue, pos + newValueSize);
	}
}

inline static void getFileDirPath(const string &filePath, string &fileDirPath) {
	fileDirPath.clear();
	if (!filePath.empty()) {
		auto pos = filePath.rfind('/');
		if (pos != string::npos)
			fileDirPath = filePath.substr(0, pos);
	}
}

/**
 *
 * charset: UTF-16LE, UTF-8
 *
 * @param fromCharset
 * @param toCharset
 * @param input
 * @return success: true
 */
static inline bool CharsetConvert(const char *fromCharset, const char *toCharset,
		const char *input, size_t inputLen, const char *output, size_t *outputLen) {
	bool ret = false;
	iconv_t conv = iconv_open(toCharset, fromCharset);
	if (conv != (iconv_t) -1) {
		char *_input = const_cast<char *>(input);
		char *_output = const_cast<char *>(output);
		if (iconv(conv, &_input, &inputLen, &_output, outputLen) != -1) {
			ret = true;
		}
		iconv_close(conv);
	}
	return ret;
}

#endif  // EXTRACT_UTILS_H
