set(TARGET extract.erofs)

set(TARGET_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

file(GLOB EXTRACT_SRCS "*.cpp")

add_executable(${TARGET} ${EXTRACT_SRCS})

target_include_directories(${TARGET} PRIVATE "include")

target_link_libraries(${TARGET} PUBLIC erofs_tool_static)
target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)

file(STRINGS "VERSION" EROFS_EXTRACT_VERSION LIMIT_COUNT 1)
target_compile_definitions(${TARGET} PRIVATE "-DEROFS_EXTRACT_VERSION=\"${EROFS_EXTRACT_VERSION}\"")
MESSAGE(STATUS "[erofs_extract] version is ${EROFS_EXTRACT_VERSION}")

set(ENV{TZ} UTC-8)
execute_process(
    COMMAND date "+%y%m%d%H%M"
    OUTPUT_VARIABLE EROFS_EXTRACT_BUILD_TIME
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
target_compile_definitions(${TARGET} PRIVATE "-DEROFS_EXTRACT_BUILD_TIME=\"-${EROFS_EXTRACT_BUILD_TIME}\"")
MESSAGE(STATUS "[erofs-extract] build time is ${EROFS_EXTRACT_BUILD_TIME}")

if (CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_custom_command(TARGET ${TARGET} POST_BUILD
        COMMAND ${CMAKE_STRIP} -w "$<TARGET_FILE:${TARGET}>"
    )
endif ()
