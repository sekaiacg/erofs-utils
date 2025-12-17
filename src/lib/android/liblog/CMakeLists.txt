set(TARGET log_static)

set(TARGET_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(TARGET_CFLAGS
    "-Wall"
    "-Werror"
    "-Wextra"
    "-Wexit-time-destructors"
    "-DLIBLOG_LOG_TAG=1006"
    "-DSNET_EVENT_LOG_TAG=1397638484"
    "-Wno-c99-designator"
    "-U__ANDROID__"
)

set(liblog_srcs
    "log.cpp"
)

list(TRANSFORM liblog_srcs PREPEND "${TARGET_SRC_DIR}/")

add_library(${TARGET} STATIC ${liblog_srcs})

target_include_directories(${TARGET} PUBLIC
    "${TARGET_SRC_DIR}/include"
)

target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
