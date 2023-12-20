#ifndef __CASE_SENSITIVE_INFO_H
#define __CASE_SENSITIVE_INFO_H

#include "Logging.h"

#if defined(__CYGWIN__)
// Code from newlib-cygwin  chattr.c
#include <errno.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <cygwin/fs.h>
#include <cygwin/version.h>

#if CYGWIN_VERSION_DLL_MAJOR < 3004
#warning "Cygwin magor version is lower than 3004, set case sensitive may not working."
#endif

/*
 * @brief Enable case sensitive on a dir.
 * @param path Give path of dir / file. if file, will look for parent dir.
 * @return 0 or errno value
 */
static inline int EnsureCaseSensitive(const char *path) {
	int ret = 0;
	if (!path) {
#ifndef NDEBUG
		LOGE("Error: %s", strerror(EINVAL));
#endif
		ret = EINVAL;
		return ret;
	}

	struct stat st;
	char *dir_path;
	uint64_t flags, new_flags;

	if (access(path, F_OK) == 0) {
		stat(path, &st);
	} else {
		if (mkdir(path, 0777) < 0) {
#ifndef NDEBUG
			LOGE("Could not create dir: %s", path);
#endif
			ret = EIO;
			return ret;
		}
	}

	dir_path = strdup(path);
	if (!S_ISDIR(st.st_mode)) {
		dirname(dir_path);
	}

	int fd;
	if (!(fd = open(dir_path, O_DIRECTORY | O_RDONLY))) {
		ret = EIO;
		goto quit;
	}

	if (ioctl(fd, (int) FS_IOC_GETFLAGS, &flags)) {
		ret = EIO;
#ifndef NDEBUG
		LOGE("ioctl: %s", strerror(errno));
#endif
		goto quit;
	}

	new_flags = flags;
	new_flags |= FS_CASESENS_FL;

	// If already case sensitive then skip
	if (new_flags == flags) {
		goto quit;
	}

	if (ioctl(fd, (int) FS_IOC_SETFLAGS, &new_flags)) {
#ifndef NDEBUG
		LOGE("ioctl: %s", strerror(errno));
		goto quit;
#endif
	}

quit:
	if (dir_path)
		free(dir_path);
	if (fd)
		close(fd);
	return ret;
}

#elif defined(_WIN32)
// Code from ookiineko@github.com
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <io.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <aclapi.h>
#include <Lmcons.h>

static char __win_strerror_buf[64 * 1024 - 1];

/*
 *@brief win_strerror
 *@param winerr
*/
static const char *win_strerror(DWORD winerr) {
	if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
					   winerr, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
					   __win_strerror_buf, sizeof(__win_strerror_buf), NULL)) {
#ifndef NDEBUG
		LOGE("FormatMessage for WinError %ld failed (WinError %ld)", winerr, GetLastError());
#endif
		return "Unknown error (win_strerror failed)";
	}

	return __win_strerror_buf;
}

static char userBuff[UNLEN + 1];

static HANDLE hToken = INVALID_HANDLE_VALUE;

static int EnsurePathAccess(const char *path, DWORD access) {
	char *pathBuff = strdup(path);
	int ret;

	if (!pathBuff) {
#ifndef NDEBUG
		perror("strdup");
#endif
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		ret = -1;
		return ret;
	}

	SECURITY_DESCRIPTOR *sd = NULL;
	ACL *oldDacl = NULL;
	ACL *newDacl = NULL;
	DWORD winerr;

	EXPLICIT_ACCESS ea = {};
	GENERIC_MAPPING _mapping = {};  // unused
	PRIVILEGE_SET _privs = {};
	DWORD _priv_size = sizeof(_privs);

	DWORD _granted = 0;  // unused
	BOOL status = FALSE;

	do {
		ret = -1;

		// owner and group info are required for the AccessCheck below
		if ((winerr = GetNamedSecurityInfo(path, SE_FILE_OBJECT,
										   OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
										   DACL_SECURITY_INFORMATION, NULL, NULL, &oldDacl, NULL, (void **) &sd))) {
			SetLastError(winerr);

#ifndef NDEBUG
			LOGE("GetNamedSecurityInfo failed: %s", win_strerror(winerr));
#endif
			break;
		}

		BuildExplicitAccessWithName(&ea, userBuff, access, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);

		// next, check if our process already have the requested permission
		if (!AccessCheck(sd, hToken, access, &_mapping, &_privs, &_priv_size, &_granted, &status)) {
#ifndef NDEBUG
			LOGE("AccessCheck failed: %s", win_strerror(GetLastError()));
#endif
			break;
		}
		if (status) {
			ret = 0;
			break;
		}  // already has the permission, skip
		// merge with the old DACL

		if ((winerr = SetEntriesInAcl(1, &ea, oldDacl, &newDacl))) {
			SetLastError(winerr);

#ifndef NDEBUG
			LOGE("SetEntriedInAcl failed: %s", win_strerror(winerr));
#endif

			break;
		}

		if ((winerr = SetNamedSecurityInfo(pathBuff, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, newDacl,
										   NULL))) {
			SetLastError(winerr);

#ifndef NDEBUG
			LOGE("SetNamedSecurityInfo failed: %s", win_strerror(winerr));
#endif

			break;
		}
		// success
		ret = 0;
	} while (false);
	// exit
	if (pathBuff)
		free(pathBuff);

	if (sd)
		LocalFree(sd);  // also frees the memory region contains oldDacl

	if (newDacl)
		LocalFree(newDacl);

	return ret;

}

__attribute__((constructor)) static void __init_creds(void) {
	DWORD dw = sizeof(userBuff);

	if (!GetUserName(userBuff, &dw)) {
		LOGE("GetUserName failed: %s", win_strerror(GetLastError()));

		assert(0);
	}

	// Ref: https://blog.aaronballman.com/2011/08/how-to-check-access-rights/

	HANDLE hProcessToken = INVALID_HANDLE_VALUE;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | STANDARD_RIGHTS_READ,
						  &hProcessToken)) {
		LOGE("OpenProcessToken failed: %s", win_strerror(GetLastError()));

		assert(0);
	}

	BOOL succeed = DuplicateToken(hProcessToken, SecurityImpersonation, &hToken);

	CloseHandle(hProcessToken);

	if (!succeed) {
		LOGE("DuplicateToken failed: %s", win_strerror(GetLastError()));

		assert(0);
	}
}

__attribute__((destructor)) static void __destroy_creds(void) {
	if (hToken != INVALID_HANDLE_VALUE)
		CloseHandle(hToken);
}

#define __FileCaseSensitiveInfo     (FILE_INFO_BY_HANDLE_CLASS)(0x17)

static_assert(__FileCaseSensitiveInfo == 0x17, "FileCaseSensitiveInfo is set to a wrong value");

#define fs_min(a, b)  (((a) < (b)) ? (a) : (b))

static bool enforce_case;

static int __open_dir_fd(const char *path, DWORD access, DWORD share_mode, int flags) {
	HANDLE h;
	int fd;

	if ((h = CreateFile(path, access, share_mode, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL)) ==
		INVALID_HANDLE_VALUE)
		return -1;

	if ((fd = _open_osfhandle((intptr_t) h, flags)) < 0) {
#ifndef NDEBUG
		LOGE("_open_osfhandle failed");
#endif
		SetLastError(ERROR_INVALID_PARAMETER);  // EINVAL
		CloseHandle(h);

		return -1;
	}
	// don't close the original handle, the ownership is transferred to the fd
	return fd;
}

static inline void EnsureCaseSensitive(const char *path, bool file = false) {
	if (!path)
		return;  // invalid call

	if (file) {
		// find out parent directory and re-run

		char *tmp = strdup(path);

		if (!tmp) {
#ifndef NDEBUG
			perror("strdup");
#endif
			assert(0);
		}

		const char *parent = dirname(tmp);

		EnsureCaseSensitive(parent, false);

		free(tmp);

		return;
	}

	struct stat buf;

	if (stat(path, &buf) < 0 || !S_ISDIR(buf.st_mode) || access(path, W_OK) != 0)
		return; // path is not a valid directory or inaccessible


	HANDLE h = INVALID_HANDLE_VALUE;
	bool success = false;
	int fd;

	if ((fd = __open_dir_fd(path, GENERIC_READ, FILE_SHARE_VALID_FLAGS, 0)) < 0) {
open_dir_fd_failed:
#ifndef NDEBUG
		LOGE("fd: %d", fd);
		LOGE("__open_dir_fd failed: %s", win_strerror(GetLastError()));
#endif

		goto quit;
	}

	if ((h = (HANDLE) _get_osfhandle(fd)) == INVALID_HANDLE_VALUE) {
get_handle_failed:
#ifndef NDEBUG
		LOGE("_get_osfhandle failed");
#endif
		goto quit;
	}

	fd = -1;  // ownership transferred

	FILE_CASE_SENSITIVE_INFO fcsi;
	DWORD winerr;

	if (!GetFileInformationByHandleEx(h, __FileCaseSensitiveInfo, &fcsi, sizeof(fcsi))) {
		winerr = GetLastError();

#ifndef NDEBUG
		LOGE("GetFileInformationByHandleEx failed: %s", win_strerror(winerr));
#endif

diag_and_quit:
#ifdef NDEBUG
		if (!enforce_case)
			goto quit;  // dont show diagnosis info if user requested to disable check
#endif
		switch (winerr) {
			case ERROR_INVALID_PARAMETER:
				LOGE("Detected: You may be on an OS version that doesn't support case sensitivity settings.");
				break;
			case ERROR_NOT_SUPPORTED:
				LOGE("Detected: Windows Subsystem for Linux may not be enabled on this machine.");
				break;
			case ERROR_ACCESS_DENIED:
				LOGE("Detected: You may not have enough rights to have this directory case sensitive with current user.");
				break;
			case ERROR_DIR_NOT_EMPTY:
				LOGE("Detected: The directory is not empty, use fsutil to set the case sensitivity before filling this directory with files.");
				break;
			default:
				// unknown error !?
				LOGE("Note: Unable to determine reason, try using fsutil to set the case sensitivity manually and see.");
				break;
		}

		goto quit;
	}

	if (fcsi.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR)
		goto done;  // already case sensitive, skip

	// reopen with write permission
	CloseHandle(h);
	h = NULL;

	if ((fd = __open_dir_fd(path, GENERIC_WRITE, FILE_SHARE_VALID_FLAGS, 0)) < 0)
		goto open_dir_fd_failed;

	if ((h = (HANDLE) _get_osfhandle(fd)) == INVALID_HANDLE_VALUE)
		goto get_handle_failed;

	fd = -1;

	// do not mixed up access with cygwin
	EnsurePathAccess(path, FILE_DELETE_CHILD);  // undocumented but required for non-administrator?

	fcsi.Flags |= FILE_CS_FLAG_CASE_SENSITIVE_DIR;

	if (!SetFileInformationByHandle(h, (FILE_INFO_BY_HANDLE_CLASS)__FileCaseSensitiveInfo, &fcsi, sizeof(fcsi))) {
		winerr = GetLastError();

#ifndef NDEBUG
		LOGE("SetFileInformationByHandle failed: %s", win_strerror(winerr));
#endif

		goto diag_and_quit;
	}

done:
	success = true;

quit:
	if (!(fd < 0))
		close(fd);

	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);

	if (!success) {
		LOGE("Friendly error: Unable to ensure case sensitivity of the directory '%s'\n"
			 "Now the program will stop in order to avoid any potential incorrect file operations.\n"
			 "Please run 'fsutil.exe file setCaseSensitiveInfo <path> enable' manually for this directory and try again.\n"
			 "You may want to make sure Windows Subsystem for Linux is enabled on this machine.\n"
			 "On OS version older than Windows 10 1803, reactOS and wine, this feature may not be available.\n", path);

		abort();
	}

	return;
}

#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#endif
#else
#error "Only support on windows platform, include this is useless"
#endif

#endif
