set(TARGET fsck.erofs)

file(GLOB FSCK_SRCS "${PROJECT_SOURCE_DIR}/fsck/*.c")

add_executable(${TARGET} ${FSCK_SRCS})

target_compile_options(${TARGET} PRIVATE ${EROFS_UTILS_DEFAULTS_CFLAGS})

target_link_libraries(${TARGET} erofs)
