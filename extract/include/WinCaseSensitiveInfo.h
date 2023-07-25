#ifndef __WIN_CASESENSIVE_H
#define __WIN_CASESENSIVE_H
#include <cstring>
#include <codecvt>
#include <locale>
#include <ntdef.h>
#include <windef.h>
#include <winternl.h>
#include <ntstatus.h>
#include <winbase.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef FILE_CASE_SENSITIVE_INFORMATION
#define FILE_CS_FLAG_CASE_SENSITIVE_DIR 0x00000001
#pragma pack(push,4)
typedef struct _FILE_CASE_SENSITIVE_INFORMATION {
  ULONG Flags;
} FILE_CASE_SENSITIVE_INFORMATION, *PFILE_CASE_SENSITIVE_INFORMATION;
#pragma pack(pop)
#endif

static inline std::wstring to_wide_string(const std::string& input) {
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	return converter.from_bytes(input);
}

/**
 * 
 * Make directory case sensitive
 * 
 * @param folder
 * @param flag
 * @return success: true
*/
static WINBOOL setCaseSensitiveInfo(std::string folder, bool flag) {

	wchar_t DosFileName[MAX_PATH] = {0};
	wchar_t wfolder[MAX_PATH] = {0};
	std::wstring wsfolder = to_wide_string(folder);
	UNICODE_STRING NtFileName;
	IO_STATUS_BLOCK IoStatusBlock;
	OBJECT_ATTRIBUTES ObjectAttrb;
	/* FILE_INFORMATION_CLASS enum: seventy one */
	FILE_INFORMATION_CLASS FileCaseSensitiveInformation = FILE_INFORMATION_CLASS(71);
	HANDLE handle;
	FILE_CASE_SENSITIVE_INFO fcsinfo;
	if (flag == true) {
		fcsinfo.Flags = FILE_CS_FLAG_CASE_SENSITIVE_DIR;
	} else {
		fcsinfo.Flags = 0;
	}
	NTSTATUS result;
	DWORD ret;
	WINBOOL rltret;

	wcsncpy(wfolder, wsfolder.c_str(), wsfolder.size());

	fprintf(stderr, "SetCaseSensitiveInfo: %s [%s]\n", 
		folder.c_str(),
		(flag == TRUE) ? "true" : "false"
	);

	ret = GetFullPathNameW(wfolder, MAX_PATH, DosFileName, NULL);
	if (!ret) {
		fprintf(stderr, "GetFullPathNameW failed return %d!\n", ret);
		return FALSE;
	}
	rltret = RtlDosPathNameToNtPathName_U(DosFileName, &NtFileName, NULL, NULL);
	if (rltret == FALSE) {
		fprintf(stderr, "RtlDosPathNameToNtPathName_U failed return false");
		return FALSE;
	}
	InitializeObjectAttributes(&ObjectAttrb, &NtFileName, 0, NULL, NULL);
	result = NtCreateFile(&handle, GENERIC_READ|GENERIC_WRITE, &ObjectAttrb, &IoStatusBlock, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
	if (result != STATUS_SUCCESS) {
		fprintf(stderr, "NtCreateFile failed to create file.\n"
						"The return NTSTATUS is %08x.\n", result);
		return FALSE;
	}
	result = NtSetInformationFile(handle, &IoStatusBlock, &fcsinfo, sizeof(fcsinfo), FileCaseSensitiveInformation);
	if (result != STATUS_SUCCESS) {
		fprintf(stderr, "NtSetInformationFile failed to set file information.\n"
						"The return NTSTATUS is %08x.\n", result);
		return FALSE;
	}
	fprintf(stderr, "Success change dir into case sensitive\n");
	return true;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif //__WIN_CASESENSIVE_H
