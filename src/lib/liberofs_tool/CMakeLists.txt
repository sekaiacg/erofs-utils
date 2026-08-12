set(TARGET erofs_tool_static)

set(TARGET_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/erofs_tool")

set(TARGET_CFLAGS
    "-Wno-c99-designator"
)

file(GLOB EROFS_TOOL_COMMON_SRCS "${TARGET_SRC_DIR}/common/*.cpp")
file(GLOB EROFS_TOOL_CPP_SRCS "${TARGET_SRC_DIR}/*.cpp")

set(EROFS_TOOL_SRCS
    ${EROFS_TOOL_COMMON_SRCS}
    ${EROFS_TOOL_CPP_SRCS}
)

add_library(${TARGET} STATIC ${EROFS_TOOL_SRCS})

target_include_directories(${TARGET} PUBLIC

    "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(${TARGET} PUBLIC "$<LINK_LIBRARY:WHOLE_ARCHIVE,erofs_utils_static>")

target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
