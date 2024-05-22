include(headers.cmake)
if (NOT CYGWIN)
	# Cygwin libcxx is not impl yet
	# Use stdc++ instead
	include(libcxx/libcxx.cmake)
endif ()
include(libbase.cmake)
include(libcutils.cmake)
include(liblog.cmake)
include(libpcre2.cmake)
include(libselinux.cmake)
include(libz.cmake)
include(liberofs.cmake)
if (CMAKE_SYSTEM_NAME MATCHES "Linux|Android")
	include(libfuse/libfuse.cmake)
elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin|CYGWIN")
	include(libext2_uuid.cmake)
endif ()

# LZ4
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(LZ4_BUILD_CLI OFF)
set(LZ4_BUILD_LEGACY_LZ4C OFF)
set(BUILD_SHARED_LIBS OFF)
set(BUILD_STATIC_LIBS ON)
add_subdirectory("${LIB_DIR}/lz4/build/cmake" "lz4")

# XZ
set(BUILD_TESTING OFF)
set(HAVE_GETOPT_LONG OFF)
set(CREATE_XZ_SYMLINKS OFF)
set(CREATE_LZMA_SYMLINKS OFF)
set(ALLOW_ATTR_IFUNC OFF)
add_subdirectory("${LIB_DIR}/xz" "xz")

# ZSTD
set(ZSTD_BUILD_STATIC ON)
set(ZSTD_BUILD_SHARED OFF)
set(ZSTD_BUILD_PROGRAMS OFF)
set(ZSTD_BUILD_CONTRIB OFF)
set(BUILD_TESTING OFF)
set(ZSTD_MULTITHREAD_SUPPORT ON)
set(DZSTD_LEGACY_SUPPORT ON)
add_subdirectory("${LIB_DIR}/zstd/build/cmake" "zstd")

if (CMAKE_SYSTEM_NAME MATCHES "Android")
	include(libpackagelistparser.cmake)
endif ()

if (CYGWIN)
	# apply cygwin patches
	execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/patch/cygwin/apply_patches.sh "${LIB_DIR}")
endif ()