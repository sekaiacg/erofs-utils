set(TARGET mkfs.erofs)

file(GLOB MKFS_SRCS "${PROJECT_SOURCE_DIR}/mkfs/*.c")

add_executable(${TARGET} ${MKFS_SRCS})

target_compile_options(${TARGET} PRIVATE ${EROFS_UTILS_DEFAULTS_CFLAGS})

target_link_libraries(${TARGET} erofs)
