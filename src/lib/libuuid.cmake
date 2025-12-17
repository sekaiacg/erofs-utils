set(TARGET uuid_static)

set(TARGET_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/e2fsprogs/lib/uuid")
set(LIBUUID_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/e2fsprogs/lib/uuid")

set(TARGET_CFLAGS
    "-Wall"
    "-Wno-pointer-arith"
    "-Wno-unused-function"
    "-Wno-unused-parameter"
)

set(libuuid_srcs
    "clear.c"
    "compare.c"
    "copy.c"
    "gen_uuid.c"
    "isnull.c"
    "pack.c"
    "parse.c"
    "unpack.c"
    "unparse.c"
    "uuid_time.c"
)
list(TRANSFORM libuuid_srcs PREPEND "${TARGET_SRC_DIR}/")

add_library(${TARGET} STATIC ${libuuid_srcs})

set_target_properties(${TARGET} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${LIBUUID_BINARY_DIR})

target_include_directories(${TARGET}
    PRIVATE "${TARGET_SRC_DIR}/../"
    PUBLIC ${TARGET_SRC_DIR}
)

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    list(REMOVE_ITEM TARGET_CFLAGS "-Werror")
    list(APPEND TARGET_CFLAGS "-Wno-error")
endif ()

target_compile_options(${TARGET} PRIVATE "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>")
