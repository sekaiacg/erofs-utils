include(headers.cmake)
include(libbase.cmake)
include(libcutils.cmake)
include(liblog.cmake)
include(libpcre2.cmake)
include(libselinux.cmake)
include(libext2_uuid.cmake)
include(libfuse/libfuse.cmake)
include(liberofs.cmake)

# Thrid part library
# LZ4
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(LZ4_BUILD_CLI OFF)
set(LZ4_BUILD_LEGACY_LZ4C OFF)
add_subdirectory("${LIB_DIR}/lz4/build/cmake" "lz4")

# XZ
set(BUILD_TESTING OFF)
set(HAVE_GETOPT_LONG OFF)
set(CREATE_XZ_SYMLINKS OFF)
set(CREATE_LZMA_SYMLINKS OFF)
add_subdirectory("${LIB_DIR}/xz" "xz")

if (CMAKE_SYSTEM_NAME MATCHES "Android")
	include(libpackagelistparser.cmake)
endif()
