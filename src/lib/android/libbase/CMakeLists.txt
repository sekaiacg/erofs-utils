set(TARGET base_static)

set(TARGET_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(TARGET_CFLAGS
    "-Wall"
    "-Werror"
    "-Wextra"
    "-D_FILE_OFFSET_BITS=64"
    "-Wexit-time-destructors"
    "-Wno-c99-designator"
)

set(libbase_srcs
    "posix_strerror_r.cpp"
    "stringprintf.cpp"
    "strings.cpp"
)

list(TRANSFORM libbase_srcs PREPEND "${TARGET_SRC_DIR}/")

add_library(${TARGET} STATIC ${libbase_srcs})

target_include_directories(${TARGET} PUBLIC "${TARGET_SRC_DIR}/include")

target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
