set(TARGET ext2_uuid)

set(TARGET_SRC_DIR "${MODULES_SRC}/e2fsprogs/lib/uuid")

set(TARGET_CFLAGS
    "-Wno-unused-function"
    "-Wno-unused-parameter"
)

set(LIBEXT2_UUID_SRCS
    "${TARGET_SRC_DIR}/clear.c"
    "${TARGET_SRC_DIR}/compare.c"
    "${TARGET_SRC_DIR}/copy.c"
    "${TARGET_SRC_DIR}/gen_uuid.c"
    "${TARGET_SRC_DIR}/isnull.c"
    "${TARGET_SRC_DIR}/pack.c"
    "${TARGET_SRC_DIR}/parse.c"
    "${TARGET_SRC_DIR}/unpack.c"
    "${TARGET_SRC_DIR}/unparse.c"
    "${TARGET_SRC_DIR}/uuid_time.c"
)

add_library(${TARGET} STATIC ${LIBEXT2_UUID_SRCS})

target_compile_options(${TARGET} PRIVATE $<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>)
