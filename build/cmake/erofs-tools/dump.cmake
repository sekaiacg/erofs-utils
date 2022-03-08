set(TARGET dump.erofs)

file(GLOB DUMP_SRCS "${PROJECT_SOURCE_DIR}/dump/*.c")

add_executable(${TARGET} ${DUMP_SRCS})

target_compile_options(${TARGET} PRIVATE ${EROFS_UTILS_DEFAULTS_CFLAGS})

target_link_libraries(${TARGET} erofs)
