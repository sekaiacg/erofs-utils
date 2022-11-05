set(TARGET erofs)

set(TARGET_SRC_DIR "${PROJECT_SOURCE_DIR}/lib")

set(EROFS_UTILS_DEFAULTS_CFLAGS
    "-Wall"
    "-Wno-ignored-qualifiers"
    "-Wno-pointer-arith"
    "-Wno-unused-parameter"
    "-Wno-unused-function"
    "-DHAVE_FALLOCATE"
    "-DHAVE_LINUX_TYPES_H"
    "-DHAVE_LIBSELINUX"
    "-DHAVE_LIBUUID"
    "-DLZ4_ENABLED"
    "-DLZ4HC_ENABLED"
    "-DHAVE_LIBLZMA"
    "-DWITH_ANDROID"
    "-DHAVE_MEMRCHR"
    "-DHAVE_SYS_IOCTL_H"
    "-DGWINSZ_IN_SYS_IOCTL"
    "-DHAVE_PWRITE64"
    -include ${PROJECT_SOURCE_DIR}/erofs-utils-version.h
    CACHE INTERNAL "erofs_utils_defaults_cflags"
)

set(LIBEROFS_SRCS
    "${TARGET_SRC_DIR}/config.c"
    "${TARGET_SRC_DIR}/io.c"
    "${TARGET_SRC_DIR}/cache.c"
    "${TARGET_SRC_DIR}/super.c"
    "${TARGET_SRC_DIR}/inode.c"
    "${TARGET_SRC_DIR}/xattr.c"
    "${TARGET_SRC_DIR}/exclude.c"
    "${TARGET_SRC_DIR}/namei.c"
    "${TARGET_SRC_DIR}/data.c"
    "${TARGET_SRC_DIR}/compress.c"
    "${TARGET_SRC_DIR}/compressor.c"
    "${TARGET_SRC_DIR}/zmap.c"
    "${TARGET_SRC_DIR}/decompress.c"
    "${TARGET_SRC_DIR}/compress_hints.c"
    "${TARGET_SRC_DIR}/hashmap.c"
    "${TARGET_SRC_DIR}/sha256.c"
    "${TARGET_SRC_DIR}/blobchunk.c"
    "${TARGET_SRC_DIR}/dir.c"
    "${TARGET_SRC_DIR}/block_list.c"
    "${TARGET_SRC_DIR}/fragments.c"
    "${TARGET_SRC_DIR}/rb_tree.c"
    "${TARGET_SRC_DIR}/dedupe.c"
    "${TARGET_SRC_DIR}/compressor_lz4.c"
    "${TARGET_SRC_DIR}/compressor_lz4hc.c"
    "${TARGET_SRC_DIR}/compressor_liblzma.c"
)

add_library(${TARGET} STATIC ${LIBEROFS_SRCS})

target_compile_options(${TARGET} PRIVATE ${EROFS_UTILS_DEFAULTS_CFLAGS})

target_link_libraries(${TARGET}
    base
    cutils
    ext2_uuid
    log
    lz4_static
    liblzma
    selinux
)
