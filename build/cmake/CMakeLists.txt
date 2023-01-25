cmake_minimum_required(VERSION 3.25)
project(erofs-utils LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_C_FLAGS "")
set(CMAKE_CXX_FLAGS "")

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# File options
add_definitions(
	"-D_FILE_OFFSET_BITS=64"
	"-D_LARGEFILE_SOURCE"
	"-DNDEBUG"
)

# Compile flags
set(GLOBAL_CFLAGS
	"-Os"
	"-fdata-sections"
	"-ffunction-sections"
	"-funwind-tables"
	"-fstack-protector-strong"
	"-D_FORTIFY_SOURCE=2"
	"-Wformat"
	"-Werror=format-security"
	"-no-canonical-prefixes"
	"-fvisibility=hidden"
	"-fvisibility-inlines-hidden"
	"-fno-exceptions"
	"-fno-rtti"
)

# Linker flags
set(GLOBAL_LDFLAGS
	"-fstack-protector-strong"
	"-Wl,--fatal-warnings"
	"-Qunused-arguments"
	"-Wl,--no-undefined"
	"-Wl,--gc-sections"
	"-static"
	"-s"
)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	list(APPEND GLOBAL_CFLAGS "-fdiagnostics-color=always")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
	list(APPEND GLOBAL_CFLAGS "-fcolor-diagnostics")
endif()

if (CMAKE_SYSTEM_NAME MATCHES "Android")
	list(APPEND GLOBAL_CFLAGS "-DANDROID" "-mllvm" "-polly")
	list(APPEND GLOBAL_LDFLAGS "-Wl,--build-id=none")
endif()

add_compile_options("$<$<COMPILE_LANGUAGE:C>:${GLOBAL_CFLAGS}>" "$<$<COMPILE_LANGUAGE:CXX>:${GLOBAL_CFLAGS}>")
add_link_options("$<$<LINK_LANGUAGE:C>:${GLOBAL_LDFLAGS}>" "$<$<LINK_LANGUAGE:CXX>:${GLOBAL_LDFLAGS}>")

set(LIB_DIR "${PROJECT_SOURCE_DIR}/../../src")
set(PROJECT_ROOT_DIR "${PROJECT_SOURCE_DIR}/../..")

execute_process(COMMAND sh
	"${PROJECT_SOURCE_DIR}/../../scripts/get-version-number"
	OUTPUT_VARIABLE PROJECT_VERSION
)
string(REGEX REPLACE "\n$" "" PROJECT_VERSION "${PROJECT_VERSION}")
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/erofs-utils-version.in"
	"${CMAKE_BINARY_DIR}/erofs-utils-version.h"
)

# Git clone submodule
execute_process(COMMAND git submodule init)
execute_process(COMMAND git submodule update)

# Start building
add_subdirectory(lib)
add_subdirectory(erofs-tools)
