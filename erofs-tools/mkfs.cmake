set(TARGET mkfs.erofs)

file(GLOB SRCS "${PROJECT_SOURCE_DIR}/mkfs/*.c") 
add_executable(${TARGET} ${SRCS})
target_link_libraries(${TARGET} 
    erofs
    cutils
    ext2_uuid
    log
    lz4_static
    selinux
    pcre
    base
    )
include_directories(
    ${PROJECT_SOURCE_DIR}/lib
    ${PROJECT_SOURCE_DIR}/include
    ${SRC}/selinux/libselinux/include
    ${SRC}/e2fsprogs/lib/uuid
    ${SRC}/core/libcutils/include
    )
link_directories(
       ${SRC}
       ${SRC}/lz4/build/cmake
       ${SRC}/pcre
)
