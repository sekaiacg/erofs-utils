set(TARGET fuse_static)

set(TARGET_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libfuse/lib")
set(LIBFUSE_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/libfuse")

set(LIBFUSE_VERSION "3.18.0")
string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$" UNUSED "${LIBFUSE_VERSION}")
set(FUSE_MAJOR_VERSION ${CMAKE_MATCH_1})
set(FUSE_MINOR_VERSION ${CMAKE_MATCH_2})
set(FUSE_HOTFIX_VERSION ${CMAKE_MATCH_3})
math(EXPR FUSE_USE_VERSION "${FUSE_MAJOR_VERSION} * 100 + ${FUSE_MINOR_VERSION}")

set(LIBFUSE_FUNC_LIST
    "copy_file_range"
    "fork"
    "fstatat"
    "openat"
    "readlinkat"
    "pipe2"
    "splice"
    "vmsplice"
    "posix_fallocate"
    "fdatasync"
    "utimensat"
    "fallocate"
)
check_fun(LIBFUSE_FUNC_LIST)
check_symbol_exists(setxattr "sys/xattr.h" HAVE_SETXATTR)
check_symbol_exists(iconv "iconv.h" HAVE_ICONV)
check_struct_has_member("struct stat" "st_atim" "sys/stat.h" HAVE_STRUCT_STAT_ST_ATIM)
check_struct_has_member("struct stat" "st_atimespec" "sys/stat.h" HAVE_STRUCT_STAT_ST_ATIMESPEC)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/libfuse_config.h.in"
    "${LIBFUSE_BINARY_DIR}/fuse_config.h"
)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/libfuse_version_config.h.in"
    "${TARGET_SRC_DIR}/../include/libfuse_config.h"
)

set(LIBFUSE_DEFAULTS_CFLAGS
    "-D_FILE_OFFSET_BITS=64"
    "-DFUSE_USE_VERSION=${FUSE_USE_VERSION}"
    "-Wno-unused-result"
    "-Wall"
    "-Werror"
    "-Wextra"
    "-Wno-error=unused-result"
    "-Wno-sign-compare"
    "-Wno-incompatible-pointer-types"
    "-Wno-missing-field-initializers"
    "-Wno-unused-function"
    "-Wno-unused-parameter"
    "-Wno-unused-variable"
    "-D_REENTRANT"
    "-DHAVE_LIBFUSE_PRIVATE_CONFIG_H"
    "-DHAVE_STRUCT_FUSE_FILE_INFO_CACHE_READDIR"
    "-DHAVE_STRUCT_FUSE_FILE_INFO_KEEP_CACHE"
    "-fno-strict-aliasing"
    CACHE INTERNAL "libfuse_defaults_cflags"
)

set(libfuse_srcs
    "buffer.c"
    "cuse_lowlevel.c"
    "fuse.c"
    "fuse_log.c"
    "fuse_loop.c"
    "fuse_loop_mt.c"
    "fuse_lowlevel.c"
    "fuse_opt.c"
    "fuse_signals.c"
    "helper.c"
    "modules/subdir.c"
    "modules/iconv.c"
    "mount.c"
    "mount_util.c"
    "compat.c"
)
list(TRANSFORM libfuse_srcs PREPEND "${TARGET_SRC_DIR}/")

if (CMAKE_SYSTEM_NAME MATCHES "Android")
    list(APPEND LIBFUSE_DEFAULTS_CFLAGS "-DFUSERMOUNT_DIR=\"/system/bin\"")
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux|Darwin")
    list(APPEND LIBFUSE_DEFAULTS_CFLAGS "-DFUSERMOUNT_DIR=\"/bin\"")
endif ()

add_library(${TARGET} STATIC ${libfuse_srcs})

set_target_properties(${TARGET} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${LIBFUSE_BINARY_DIR})

target_include_directories(${TARGET}
    PRIVATE
    ${TARGET_SRC_DIR}
    PUBLIC
    "${TARGET_SRC_DIR}/../include"
    ${LIBFUSE_BINARY_DIR}
)

target_compile_options(${TARGET} PUBLIC
    "$<$<COMPILE_LANGUAGE:C>:${LIBFUSE_DEFAULTS_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${LIBFUSE_DEFAULTS_CFLAGS}>"
)
