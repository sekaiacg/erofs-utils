set(TARGET fuse)

set(TARGET_SRC_DIR "${MODULES_SRC}/libfuse/lib")

set(LIBFUSE_DEFAULTS_CFLAGS
    "-DFUSE_USE_VERSION=312"
    "-Wall"
    "-Wextra"
    "-Wno-sign-compare"
    "-Wno-incompatible-pointer-types"
    "-Wno-missing-field-initializers"
    "-Wno-unused-result"
    "-Wno-implicit-function-declaration"
    "-Wno-unused-parameter"
    "-Wno-unused-variable"
    CACHE INTERNAL "libfuse_defaults_cflags"
)

set(LIBFUSE_SRCS
    "${TARGET_SRC_DIR}/buffer.c"
    "${TARGET_SRC_DIR}/cuse_lowlevel.c"
    "${TARGET_SRC_DIR}/fuse.c"
    "${TARGET_SRC_DIR}/fuse_log.c"
    "${TARGET_SRC_DIR}/fuse_loop.c"
    "${TARGET_SRC_DIR}/fuse_loop_mt.c"
    "${TARGET_SRC_DIR}/fuse_lowlevel.c"
    "${TARGET_SRC_DIR}/fuse_opt.c"
    "${TARGET_SRC_DIR}/fuse_signals.c"
    "${TARGET_SRC_DIR}/helper.c"
    "${TARGET_SRC_DIR}/modules/subdir.c"
    "${TARGET_SRC_DIR}/modules/iconv.c"
    "${TARGET_SRC_DIR}/mount.c"
    "${TARGET_SRC_DIR}/mount_util.c"
    "${TARGET_SRC_DIR}/compat.c"
)


file(GLOB LIBFUSE_CONFIG_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/libfuse/*.h")
file(COPY ${LIBFUSE_CONFIG_HEADER} DESTINATION ${TARGET_SRC_DIR})

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    list(APPEND LIBFUSE_DEFAULTS_CFLAGS "-DFUSERMOUNT_DIR=\"/bin\"")
elseif (CMAKE_SYSTEM_NAME MATCHES "Android")
    list(APPEND LIBFUSE_DEFAULTS_CFLAGS "-DFUSERMOUNT_DIR=\"/system/bin\"")
endif()

add_library(${TARGET} STATIC ${LIBFUSE_SRCS})

target_include_directories(${TARGET} PRIVATE
    "${MODULES_SRC}/libfuse/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/libfuse"
)

target_link_libraries(${TARGET} dl)
target_link_options(${TARGET} PRIVATE "-Wl,--version-script,${TARGET_SRC_DIR}/fuse_versionscript")
target_compile_options(${TARGET} PRIVATE ${LIBFUSE_DEFAULTS_CFLAGS})
