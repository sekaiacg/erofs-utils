include(headers.cmake)
include(libcxx.cmake)
include(libbase.cmake)
include(libcutils.cmake)
include(liblog.cmake)
include(libpcre2.cmake)
include(libselinux.cmake)
include(libz.cmake)
include(liberofs.cmake)
if (CMAKE_SYSTEM_NAME MATCHES "Linux|Android")
	include(libfuse/libfuse.cmake)
elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
	include(libext2_uuid.cmake)
endif ()

# Thrid part library
# LZ4
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(LZ4_BUILD_CLI OFF)
set(LZ4_BUILD_LEGACY_LZ4C OFF)
add_subdirectory("${LIB_DIR}/lz4/build/cmake" "lz4")

# XZ
execute_process(COMMAND readlink -f "${LIB_DIR}/xz/CMakeLists.txt" OUTPUT_VARIABLE PATH_TARGET_FILE)
string(REGEX REPLACE "\n$" "" PATH_TARGET_FILE "${PATH_TARGET_FILE}")
execute_process(COMMAND patch -N
	"${PATH_TARGET_FILE}"
	"${CMAKE_CURRENT_SOURCE_DIR}/patch/xz_cmakelists.patch"
)
set(BUILD_TESTING OFF)
set(HAVE_GETOPT_LONG OFF)
set(CREATE_XZ_SYMLINKS OFF)
set(CREATE_LZMA_SYMLINKS OFF)
add_subdirectory("${LIB_DIR}/xz" "xz")

if (CMAKE_SYSTEM_NAME MATCHES "Android")
	include(libpackagelistparser.cmake)
endif ()
