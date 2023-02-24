#ifndef _EXTRACT_LOGGING_H
#define _EXTRACT_LOGGING_H

/**
 *	Partial code reference：https://blog.csdn.net/m_pfly_fish/article/details/118541894
 *	Partial code reference: erofs/print.h
 */
#define LOG_COLOR_BLACK     "30"
#define LOG_COLOR_RED       "31"
#define LOG_COLOR_RED2      "91"
#define LOG_COLOR_GREEN     "32"
#define LOG_COLOR_GREEN2    "92"
#define LOG_COLOR_BROWN     "33"
#define LOG_COLOR_BROWN2    "93"
#define LOG_COLOR_BLUE      "34"
#define LOG_COLOR_BLUE2     "94"
#define LOG_COLOR_PURPLE    "35"

#define LOG_COLOR(COLOR)    "\033[0;" COLOR "m"
#define LOG_BOLD(COLOR)     "\033[1;" COLOR "m"
#define LOG_RESET_COLOR     "\033[0m"

#define RED                 LOG_COLOR(LOG_COLOR_RED)
#define RED_BOLD            LOG_BOLD(LOG_COLOR_RED)
#define RED2                LOG_COLOR(LOG_COLOR_RED2)
#define RED2_BOLD           LOG_BOLD(LOG_COLOR_RED2)
#define GREEN2_BOLD         LOG_BOLD(LOG_COLOR_GREEN2)
#define BROWN               LOG_COLOR(LOG_COLOR_BROWN)
#define BROWN2              LOG_COLOR(LOG_COLOR_BROWN2)
#define BROWN2_BOLD         LOG_BOLD(LOG_COLOR_BROWN2)
#define BROWN_BOLD          LOG_BOLD(LOG_COLOR_BROWN)
#define BLUE                LOG_COLOR(LOG_COLOR_BLUE)
#define BLUE_BOLD           LOG_BOLD(LOG_COLOR_BLUE)
#define BLUE2_BOLD          LOG_BOLD(LOG_COLOR_BLUE2)
#define COLOR_NONE          LOG_RESET_COLOR

#ifndef LOG_TAG
#define LOG_TAG             "Extract"
#endif

/**
 * _log_print
 *
 * @param fmt
 * @param ...
 */
static inline void _log_print(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fflush(stdout);
}

#ifndef NDEBUG
#define EX_FUNC_LINE_FMT "%s:%d, "
#define ex_fmt(fmt) LOG_TAG ": " EX_FUNC_LINE_FMT fmt "\n"
#define EX_FMT_FUNC_LINE(fmt) ex_fmt(fmt), __func__, __LINE__
#define ex_tag_color_fmt(color, fmt) color LOG_TAG ": " COLOR_NONE EX_FUNC_LINE_FMT fmt "\n"
#define EX_TAG_C_FMT_FUNC_LINE(color, fmt) ex_tag_color_fmt(color, fmt), __func__, __LINE__
#define LOGCD(fmt, ...) _log_print(EX_TAG_C_FMT_FUNC_LINE(BLUE2_BOLD, fmt), ##__VA_ARGS__)
#define LOGD(fmt, ...) _log_print(EX_FMT_FUNC_LINE(fmt), ##__VA_ARGS__)
#else
#define ex_fmt(fmt) LOG_TAG ": " fmt "\n"
#define EX_FMT_FUNC_LINE(fmt) ex_fmt(fmt)
#define ex_tag_color_fmt(color, fmt) color LOG_TAG ": " COLOR_NONE fmt "\n"
#define EX_TAG_C_FMT_FUNC_LINE(color, fmt) ex_tag_color_fmt(color, fmt)
#define LOGCD(fmt, ...) 0
#define LOGD(fmt, ...) 0
#endif

#define LOGCV(fmt, ...) _log_print(EX_TAG_C_FMT_FUNC_LINE(BLUE2_BOLD, fmt), ##__VA_ARGS__)
#define LOGCI(fmt, ...) _log_print(EX_TAG_C_FMT_FUNC_LINE(BROWN2_BOLD, fmt), ##__VA_ARGS__)
#define LOGCW(fmt, ...) _log_print(EX_TAG_C_FMT_FUNC_LINE(BROWN2_BOLD, fmt), ##__VA_ARGS__)
#define LOGCE(fmt, ...) _log_print(EX_TAG_C_FMT_FUNC_LINE(RED2_BOLD, fmt), ##__VA_ARGS__)

#define LOGV(fmt, ...) _log_print(EX_FMT_FUNC_LINE(fmt), ##__VA_ARGS__)
#define LOGI(fmt, ...) _log_print(EX_FMT_FUNC_LINE(fmt), ##__VA_ARGS__)
#define LOGW(fmt, ...) _log_print(EX_FMT_FUNC_LINE(fmt), ##__VA_ARGS__)
#define LOGE(fmt, ...) _log_print(EX_FMT_FUNC_LINE(fmt), ##__VA_ARGS__)

#endif // _EXTRACT_LOGGING_H
