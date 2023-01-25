set(TARGET pcre2)

set(TARGET_SRC_DIR "${LIB_DIR}/pcre/src")

set(TARGET_CFLAGS
	"-DHAVE_CONFIG_H"
	"-Wall"
	"-Werror"
	"-DPCRE2_CODE_UNIT_WIDTH=8"
)

set(libpcre2_srcs
	"${TARGET_SRC_DIR}/pcre2_auto_possess.c"
	"${TARGET_SRC_DIR}/pcre2_compile.c"
	"${TARGET_SRC_DIR}/pcre2_config.c"
	"${TARGET_SRC_DIR}/pcre2_context.c"
	"${TARGET_SRC_DIR}/pcre2_convert.c"
	"${TARGET_SRC_DIR}/pcre2_dfa_match.c"
	"${TARGET_SRC_DIR}/pcre2_error.c"
	"${TARGET_SRC_DIR}/pcre2_extuni.c"
	"${TARGET_SRC_DIR}/pcre2_find_bracket.c"
	"${TARGET_SRC_DIR}/pcre2_maketables.c"
	"${TARGET_SRC_DIR}/pcre2_match.c"
	"${TARGET_SRC_DIR}/pcre2_match_data.c"
	"${TARGET_SRC_DIR}/pcre2_jit_compile.c"
	"${TARGET_SRC_DIR}/pcre2_newline.c"
	"${TARGET_SRC_DIR}/pcre2_ord2utf.c"
	"${TARGET_SRC_DIR}/pcre2_pattern_info.c"
	"${TARGET_SRC_DIR}/pcre2_script_run.c"
	"${TARGET_SRC_DIR}/pcre2_serialize.c"
	"${TARGET_SRC_DIR}/pcre2_string_utils.c"
	"${TARGET_SRC_DIR}/pcre2_study.c"
	"${TARGET_SRC_DIR}/pcre2_substitute.c"
	"${TARGET_SRC_DIR}/pcre2_substring.c"
	"${TARGET_SRC_DIR}/pcre2_tables.c"
	"${TARGET_SRC_DIR}/pcre2_ucd.c"
	"${TARGET_SRC_DIR}/pcre2_valid_utf.c"
	"${TARGET_SRC_DIR}/pcre2_xclass.c"
	"${TARGET_SRC_DIR}/pcre2_chartables.c"
)

add_library(${TARGET} STATIC ${libpcre2_srcs})

target_include_directories(${TARGET} PRIVATE ${libpcre2_headers})

target_compile_options(${TARGET} PRIVATE
	"$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
	"$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
