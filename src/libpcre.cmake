set(TARGET pcre)

add_library(${TARGET} STATIC
        ${SRC}/pcre/src/pcre2_auto_possess.c
        ${SRC}/pcre/src/pcre2_compile.c
        ${SRC}/pcre/src/pcre2_config.c
        ${SRC}/pcre/src/pcre2_context.c
        ${SRC}/pcre/src/pcre2_convert.c
        ${SRC}/pcre/src/pcre2_dfa_match.c
        ${SRC}/pcre/src/pcre2_error.c
        ${SRC}/pcre/src/pcre2_extuni.c
        ${SRC}/pcre/src/pcre2_find_bracket.c
        ${SRC}/pcre/src/pcre2_maketables.c
        ${SRC}/pcre/src/pcre2_match.c
        ${SRC}/pcre/src/pcre2_match_data.c
        ${SRC}/pcre/src/pcre2_jit_compile.c
        ${SRC}/pcre/src/pcre2_newline.c
        ${SRC}/pcre/src/pcre2_ord2utf.c
        ${SRC}/pcre/src/pcre2_pattern_info.c
        ${SRC}/pcre/src/pcre2_script_run.c
        ${SRC}/pcre/src/pcre2_serialize.c
        ${SRC}/pcre/src/pcre2_string_utils.c
        ${SRC}/pcre/src/pcre2_study.c
        ${SRC}/pcre/src/pcre2_substitute.c
        ${SRC}/pcre/src/pcre2_substring.c
        ${SRC}/pcre/src/pcre2_tables.c
        ${SRC}/pcre/src/pcre2_ucd.c
        ${SRC}/pcre/src/pcre2_valid_utf.c
        ${SRC}/pcre/src/pcre2_xclass.c
        ${SRC}/pcre/src/pcre2_chartables.c)

target_compile_definitions(${TARGET} PRIVATE -DHAVE_CONFIG_H -DPCRE2_CODE_UNIT_WIDTH=8)

target_include_directories(${TARGET} PUBLIC
    ${SRC}/pcre/include
    )
    
