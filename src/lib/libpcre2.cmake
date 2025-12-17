set(TARGET pcre2_static)

set(TARGET_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/pcre/src")
set(LIBPCRE2_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/pcre2")

set(TARGET_CFLAGS
    "-DHAVE_CONFIG_H"
    "-Wall"
    "-Werror"
    "-DPCRE2_CODE_UNIT_WIDTH=8"
)

set(libpcre2_srcs
    "pcre2_auto_possess.c"
    "pcre2_chartables.c"
    "pcre2_chkdint.c"
    "pcre2_compile.c"
    "pcre2_config.c"
    "pcre2_context.c"
    "pcre2_convert.c"
    "pcre2_dfa_match.c"
    "pcre2_error.c"
    "pcre2_extuni.c"
    "pcre2_find_bracket.c"
    "pcre2_jit_compile.c"
    "pcre2_maketables.c"
    "pcre2_match.c"
    "pcre2_match_data.c"
    "pcre2_newline.c"
    "pcre2_ord2utf.c"
    "pcre2_pattern_info.c"
    "pcre2_script_run.c"
    "pcre2_serialize.c"
    "pcre2_string_utils.c"
    "pcre2_study.c"
    "pcre2_substitute.c"
    "pcre2_substring.c"
    "pcre2_tables.c"
    "pcre2_ucd.c"
    "pcre2_valid_utf.c"
    "pcre2_xclass.c"
)
list(TRANSFORM libpcre2_srcs PREPEND "${TARGET_SRC_DIR}/")

add_library(${TARGET} STATIC ${libpcre2_srcs})

set_target_properties(${TARGET} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${LIBPCRE2_BINARY_DIR})

target_include_directories(${TARGET} PRIVATE ${TARGET_SRC_DIR})
target_include_directories(${TARGET} PUBLIC "${TARGET_SRC_DIR}/../include")

target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
