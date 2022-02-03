cmake_minimum_required(VERSION 3.14.2)
project(erofs-utils)

set(CMAKE_CXX_STANDARD 17)
# set global cflags and cxxflags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wno-ignored-qualifiers -Wno-pointer-arith -Wno-unused-parameter -Wno-unused-function -DHAVE_FALLOCATE -DHAVE_LINUX_TYPES_H -DHAVE_LIBSELINUX -DHAVE_LIBUUID -DLZ4_ENABLED -DLZ4HC_ENABLED -DWITH_ANDROID ")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-ignored-qualifiers -Wno-pointer-arith -Wno-unused-parameter -Wno-unused-function -DHAVE_FALLOCATE -DHAVE_LINUX_TYPES_H -DHAVE_LIBSELINUX -DHAVE_LIBUUID -DLZ4_ENABLED -DLZ4HC_ENABLED -DWITH_ANDROID")

set(CMAKE_EXE_LINKER_FLAGS "-static")

set(SRC ${PROJECT_SOURCE_DIR}/src)

# git clone submodule
execute_process(COMMAND git submodule init)
execute_process(COMMAND git submodule update)

# thrid part library
add_subdirectory(src/lz4/build/cmake)

# start building
add_subdirectory(src)
add_subdirectory(erofs-tools)

