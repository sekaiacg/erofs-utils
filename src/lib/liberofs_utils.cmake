set(TARGET erofs_utils_static)

set(TARGET_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/erofs-utils")
set(LIBEROFS_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/liberofs")

# Check function and header
set(liberofs_include_list
    "execinfo.h"
    "endian.h"
    "pthread.h"
    "unistd.h"
    "linux/falloc.h"
    "linux/fs.h"
    "linux/types.h"
    "linux/xattr.h"
    "sys/ioctl.h"
    "sys/random.h"
    "sys/resource.h"
    "sys/sendfile.h"
    "sys/sysmacros.h"
    "sys/uio.h"
    "sys/xattr.h"
)

set(liberofs_function_list
    "backtrace"
    "fallocate"
    "getrlimit"
    "pwritev"
    "sysconf"
    "utimensat"
)
if (CMAKE_SYSTEM_NAME MATCHES "Linux|Android")
    list(APPEND liberofs_function_list
        "copy_file_range"
        "memrchr"
        "pread64"
        "pwrite64"
        "posix_fadvise"
        "getrandom"
        "sendfile"
    )
    if (NOT RUN_ON_WSL)
        list(APPEND liberofs_function_list
            "lgetxattr"
            "llistxattr"
        )
    else ()
        message(STATUS "[erofs_utils]: Run WSL")
    endif ()
endif ()

set(common_link_libs)

if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(DARWIN_CFLAGS "-DHAVE_LIBUUID")
    list(APPEND common_link_libs uuid_static)
endif ()

check_include(liberofs_include_list)
check_fun(liberofs_function_list)
check_symbol_exists(lseek64 "unistd.h" HAVE_LSEEK64_PROTOTYPE)
check_symbol_exists(TIOCGWINSZ "sys/ioctl.h" GWINSZ_IN_SYS_IOCTL)
check_struct_has_member("struct stat" "st_atim" "sys/stat.h" HAVE_STRUCT_STAT_ST_ATIM)
check_struct_has_member("struct stat" "st_atimespec" "sys/stat.h" HAVE_STRUCT_STAT_ST_ATIMESPEC)

patch_files(
    "${TARGET_SRC_DIR}/lib"
    "${CMAKE_CURRENT_SOURCE_DIR}/patch/erofs-utils/0001-skip_dir.patch"
)
patch_file(
    "${TARGET_SRC_DIR}/lib/liberofs_sha256.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/patch/erofs-utils/liberofs_sha256.h.patch"
)

execute_process(COMMAND sh -c
    "scripts/get-version-number"
    WORKING_DIRECTORY "${TARGET_SRC_DIR}"
    OUTPUT_VARIABLE PROJECT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX REPLACE "-dirty$" "" PROJECT_VERSION "${PROJECT_VERSION}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/liberofs_utils_version.h.in"
    "${LIBEROFS_BINARY_DIR}/liberofs_utils_version.h"
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/liberofs_utils_config.h.in"
    "${LIBEROFS_BINARY_DIR}/config.h"
)

set(LIBEROFS_STATIC_DEFAULTS_CFLAGS
    "-Wall"
    "-Wno-ignored-qualifiers"
    "-Wno-pointer-arith"
    "-Wno-unused-parameter"
    "-Wno-unused-function"
    "-Wno-deprecated-declarations"
    "-Wno-c99-designator"
    ${DARWIN_CFLAGS}
)

if (NOT DEFINED MAX_BLOCK_SIZE)
    set(MAX_BLOCK_SIZE 4096)
endif ()
if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    if (MAX_BLOCK_SIZE LESS 16384)
        set(MAX_BLOCK_SIZE 16384)
    endif ()
endif ()
list(APPEND LIBEROFS_STATIC_DEFAULTS_CFLAGS "-DEROFS_MAX_BLOCK_SIZE=${MAX_BLOCK_SIZE}")

set(liberofs_utils_srcs
    "config.c"
    "io.c"
    "cache.c"
    "super.c"
    "inode.c"
    "xattr.c"
    "exclude.c"
    "namei.c"
    "data.c"
    "compress.c"
    "compressor.c"
    "zmap.c"
    "decompress.c"
    "compress_hints.c"
    "hashmap.c"
    "sha256.c"
    "blobchunk.c"
    "dir.c"
    "fragments.c"
    "dedupe.c"
    "uuid_unparse.c"
    "uuid.c"
    "tar.c"
    "block_list.c"
    "rebuild.c"
    "diskbuf.c"
    "bitops.c"
    "dedupe_ext.c"
    "vmdk.c"
    "metabox.c"
    "global.c"
    "importer.c"
    "base64.c"
    "compressor_lz4.c"
    "compressor_lz4hc.c"
    "compressor_liblzma.c"
    "kite_deflate.c"
    "compressor_deflate.c"
    "compressor_libzstd.c"
    "gzran.c"
    "workqueue.c"
)
list(TRANSFORM liberofs_utils_srcs PREPEND "${TARGET_SRC_DIR}/lib/")

add_library(${TARGET} STATIC ${liberofs_utils_srcs})

set_target_properties(${TARGET} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${LIBEROFS_BINARY_DIR})

target_precompile_headers(${TARGET}
    PRIVATE
    "${LIBEROFS_BINARY_DIR}/liberofs_utils_version.h"
    PUBLIC
    "${LIBEROFS_BINARY_DIR}/config.h"
)

target_include_directories(${TARGET} PUBLIC
    "${TARGET_SRC_DIR}/include"
    "${TARGET_SRC_DIR}/lib"
    "${LIBEROFS_BINARY_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/xz/src/liblzma/api"
)

list(APPEND common_link_libs
    xxhash
    base_static
    cutils_static
    pcre2_static
    selinux_static
    lz4_static
    liblzma
    z_static
    libzstd_static
)

target_link_libraries(${TARGET} PUBLIC "$<LINK_LIBRARY:WHOLE_ARCHIVE,${common_link_libs}>")

target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${LIBEROFS_STATIC_DEFAULTS_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${LIBEROFS_STATIC_DEFAULTS_CFLAGS}>"
)
