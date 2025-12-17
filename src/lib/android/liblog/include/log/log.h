#ifndef __LOGGING_LOG_H
#define __LOGGING_LOG_H

#include <cstdarg>
#include <cstdio>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LOG_TAG
#define LOG_TAG NULL
#endif

/**
* _log_print_e
*
* @param fmt
* @param ...
*/
void _log_print_e(const char *fmt, ...);

#define EX_FUNC_LINE_FMT "%s:%d, "
#define EX_FMT_FUNC_LINE(fmt) EX_FUNC_LINE_FMT fmt "\n", __func__, __LINE__

#ifndef ALOGE
#define ALOGE(tag, ...) _log_print_e(EX_FMT_FUNC_LINE(tag), ##__VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif

#endif // __LOGGING_LOG_H
