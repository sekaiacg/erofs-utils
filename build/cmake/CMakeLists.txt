cmake_minimum_required(VERSION 3.20)
project(erofs-utils)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    add_compile_options (-fdiagnostics-color=always)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    add_compile_options (-fcolor-diagnostics)
endif()

if(DEFINED EROFS_C_FLAGS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EROFS_C_FLAGS}")
endif()

if(DEFINED EROFS_CXX_FLAGS)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EROFS_CXX_FLAGS}")
endif()

if (DEFINED EROFS_LINKER_FLAGS)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${EROFS_LINKER_FLAGS}")
else ()
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -static -s")
endif()

set(MODULES_SRC "${PROJECT_SOURCE_DIR}/../../src")
set(PROJECT_SOURCE_DIR "${PROJECT_SOURCE_DIR}/../..")

execute_process(COMMAND sh "${PROJECT_SOURCE_DIR}/scripts/get-version-number" OUTPUT_VARIABLE PROJECT_VERSION)
string(REGEX REPLACE "\n$" "" PROJECT_VERSION "${PROJECT_VERSION}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/erofs-utils-version.in"
    "${PROJECT_SOURCE_DIR}/erofs-utils-version.h"
)

# git clone submodule
execute_process(COMMAND git submodule init)
execute_process(COMMAND git submodule update)

# thrid part library
add_subdirectory("${MODULES_SRC}/lz4/build/cmake" "modules/lz4")
set(BUILD_TESTING OFF)
set(CREATE_XZ_SYMLINKS OFF)
set(CREATE_LZMA_SYMLINKS OFF)
add_subdirectory("${MODULES_SRC}/xz" "modules/xz")

# header
include_directories(
    "${PROJECT_SOURCE_DIR}/lib"
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/src/lz4/lib"
    "${PROJECT_SOURCE_DIR}/src/xz/src/liblzma/api"
    "${MODULES_SRC}/core/libcutils/include"
    "${MODULES_SRC}/e2fsprogs/lib"
    "${MODULES_SRC}/e2fsprogs/lib/uuid"
    "${MODULES_SRC}/selinux/libselinux/include"
    "${MODULES_SRC}/logging/liblog/include"
)

# start building
add_subdirectory(modules)
add_subdirectory(erofs-tools)
