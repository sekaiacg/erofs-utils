cmake_minimum_required(VERSION 3.25...3.28)
project(erofs-utils LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# File options
add_definitions(
	"-D_FILE_OFFSET_BITS=64"
	"-D_LARGEFILE_SOURCE"
	"-D_LARGEFILE64_SOURCE"
)

if (NOT MAX_BLOCK_SIZE)
	try_run(CHECK_MAX_BLOCK_SIZE_RESULT
		CHECK_MAX_BLOCK_SIZE_COMPILE_RESULT
		${CMAKE_CURRENT_BINARY_DIR}/sources
		${CMAKE_CURRENT_SOURCE_DIR}/sources/checkMaxBlockSize.c
		NO_CACHE
		RUN_OUTPUT_VARIABLE erofs_cv_max_block_size
	)
	if (erofs_cv_max_block_size GREATER 0)
		add_definitions(-DEROFS_MAX_BLOCK_SIZE=${erofs_cv_max_block_size})
	else ()
		add_definitions(-DEROFS_MAX_BLOCK_SIZE=4096)
	endif ()
else ()
	add_definitions(-DEROFS_MAX_BLOCK_SIZE=${MAX_BLOCK_SIZE})
endif ()

# Compile flags
set(GLOBAL_CFLAGS
	"-Wformat"
	"-Werror=format-security"
	"-no-canonical-prefixes"
	"-fdata-sections"
	"-ffunction-sections"
	"-fvisibility=hidden"
	"-fvisibility-inlines-hidden"
	"-funwind-tables"
	"-fstack-protector-strong"
	"-fno-exceptions"
	"-fno-rtti"
)
if (NOT CYGWIN)
	# Cygwin libcxx has not impl yet.
	list(APPEND GLOBAL_CFLAGS
		"-nostdinc++"
	)
endif()

set(GLOBAL_CFLAGS_RELEASE
	"-Os"
	"-D_FORTIFY_SOURCE=2"
)

# Linker flags
set(GLOBAL_LDFLAGS
	"-fstack-protector-strong"
	"-Qunused-arguments"
)
set(GLOBAL_LDFLAGS_RELEASE)

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
	list(APPEND GLOBAL_LDFLAGS "-Wl,-dead_strip,-S,-x")
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux|Android")
	list(APPEND GLOBAL_CFLAGS "-fno-semantic-interposition")
	list(APPEND GLOBAL_LDFLAGS "-Wl,--no-undefined" "-static")
	list(APPEND GLOBAL_LDFLAGS_RELEASE "-Wl,-s,-x,--gc-sections")
	if (CMAKE_SYSTEM_NAME MATCHES "Android")
		list(APPEND GLOBAL_CFLAGS "-DANDROID" "-mllvm" "-polly")
	endif ()
elseif (CMAKE_SYSTEM_NAME MATCHES "CYGWIN")
	list(APPEND GLOBAL_CFLAGS "-static")
	list(APPEND GLOBAL_LDFLAGS_RELEASE "-Wl,-s,-x,--gc-sections" "-static")
endif ()

if (CMAKE_BUILD_TYPE STREQUAL "Release")
	list(APPEND GLOBAL_CFLAGS ${GLOBAL_CFLAGS_RELEASE})
	list(APPEND GLOBAL_LDFLAGS ${GLOBAL_LDFLAGS_RELEASE})
	if (ENABLE_FULL_LTO)
		list(APPEND GLOBAL_CFLAGS "-flto=full")
		if (CMAKE_SYSTEM_NAME MATCHES "Android")
			# https://github.com/android/ndk/issues/1461
			list(APPEND GLOBAL_LDFLAGS "-T${CMAKE_CURRENT_SOURCE_DIR}/lto_fix.lds")
		endif ()
		if (NOT CMAKE_SYSTEM_NAME MATCHES "Darwin|CYGWIN")
			# Cygwin lld is not work. cause have no __begin_base__ and __bss_base__ and exit also
			list(APPEND GLOBAL_LDFLAGS "-fuse-ld=lld")
			list(APPEND GLOBAL_LDFLAGS_RELEASE "-Wl,-icf=safe,--lto-O3")
		endif ()
	endif ()
	add_definitions("-DNDEBUG")
elseif (CMAKE_BUILD_TYPE STREQUAL "Debug")
	list(APPEND GLOBAL_CFLAGS "-O0" "-g")
endif ()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	list(APPEND GLOBAL_CFLAGS "-fdiagnostics-color=always")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
	list(APPEND GLOBAL_CFLAGS "-fcolor-diagnostics")
endif ()

add_compile_options("$<$<COMPILE_LANGUAGE:C>:${GLOBAL_CFLAGS}>" "$<$<COMPILE_LANGUAGE:CXX>:${GLOBAL_CFLAGS}>")
add_link_options("$<$<LINK_LANGUAGE:C>:${GLOBAL_LDFLAGS}>" "$<$<LINK_LANGUAGE:CXX>:${GLOBAL_LDFLAGS}>")

set(LIB_DIR "${PROJECT_SOURCE_DIR}/../../src")
set(PROJECT_ROOT_DIR "${PROJECT_SOURCE_DIR}/../..")

execute_process(COMMAND sh -c
	"cd ${PROJECT_SOURCE_DIR}/../../ && scripts/get-version-number"
	OUTPUT_VARIABLE PROJECT_VERSION
)
string(REGEX REPLACE "\n$" "" PROJECT_VERSION "${PROJECT_VERSION}")
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/erofs-utils-version.h.in"
	"${CMAKE_BINARY_DIR}/erofs-utils-version.h"
)

# Git clone submodule
execute_process(COMMAND git submodule init)
execute_process(COMMAND git submodule update)

# Start building
add_subdirectory(lib)
add_subdirectory(erofs-tools)
