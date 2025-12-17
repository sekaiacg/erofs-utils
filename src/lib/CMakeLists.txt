if (ENABLE_LIBCXX)
    include(libcxx.cmake)
endif ()
if (ENABLE_LIBFUSE)
    include(libfuse.cmake)
endif ()
include(libpcre2.cmake)
include(libselinux.cmake)
include(libz.cmake)
include(libuuid.cmake)
add_subdirectory(android)
include(liberofs_utils.cmake)

# xxHash
set(BUILD_SHARED_LIBS OFF)
set(XXHASH_BUILD_XXHSUM OFF)
add_subdirectory("xxHash/build/cmake" "xxHash")

# LZ4
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(LZ4_BUILD_CLI OFF)
set(LZ4_BUILD_LEGACY_LZ4C OFF)
set(BUILD_SHARED_LIBS OFF)
set(BUILD_STATIC_LIBS ON)
add_subdirectory("lz4/build/cmake" "lz4")

## XZ
set(BUILD_TESTING OFF)
set(XZ_NLS OFF)
set(XZ_TOOL_XZ OFF)
set(XZ_TOOL_LZMADEC OFF)
set(XZ_TOOL_LZMAINFO OFF)
set(XZ_TOOL_XZDEC OFF)
add_subdirectory("xz" "xz")

## ZSTD
set(BUILD_TESTING OFF)
set(ZSTD_BUILD_CONTRIB OFF)
set(ZSTD_BUILD_PROGRAMS OFF)
set(ZSTD_BUILD_SHARED OFF)
set(ZSTD_BUILD_STATIC ON)
set(ZSTD_MULTITHREAD_SUPPORT ON)
set(DZSTD_LEGACY_SUPPORT ON)
add_subdirectory("zstd/build/cmake" "zstd")
