set(TARGET ext2_uuid)

add_library(${TARGET} STATIC
    ${SRC}/e2fsprogs/lib/uuid/clear.c
    ${SRC}/e2fsprogs/lib/uuid/compare.c
    ${SRC}/e2fsprogs/lib/uuid/copy.c
    ${SRC}/e2fsprogs/lib/uuid/gen_uuid.c
    ${SRC}/e2fsprogs/lib/uuid/isnull.c
    ${SRC}/e2fsprogs/lib/uuid/pack.c
    ${SRC}/e2fsprogs/lib/uuid/parse.c
    ${SRC}/e2fsprogs/lib/uuid/unpack.c
    ${SRC}/e2fsprogs/lib/uuid/unparse.c
    ${SRC}/e2fsprogs/lib/uuid/uuid_time.c
    )
    
include_directories(
    ${SRC}/e2fsprogs/lib
    ${SRC}/core/libsparse/include
    ${SRC}/e2fsprogs/lib
    ${SRC}/e2fsprogs/misc
    ${SRC}/e2fsprogs/lib/ext2fs
    ${SRC}/selinux/libselinux/include
    ${SRC}/core/libcutils/include
    )
