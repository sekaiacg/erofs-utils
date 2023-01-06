set(TARGET fuse.erofs)

file(GLOB FUSE_SRCS "${PROJECT_SOURCE_DIR}/fuse/*.c")

add_executable(${TARGET} ${FUSE_SRCS})

target_compile_options(${TARGET} PRIVATE
    ${EROFS_UTILS_DEFAULTS_CFLAGS}
    ${LIBFUSE_DEFAULTS_CFLAGS}
)

target_include_directories(${TARGET} PRIVATE
    "${MODULES_SRC}/libfuse/include"
)

target_link_libraries(${TARGET} erofs fuse)
