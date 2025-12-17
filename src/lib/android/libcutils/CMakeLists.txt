set(TARGET cutils_static)

set(TARGET_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(TARGET_CFLAGS
    "-Wno-exit-time-destructors"
    "-Wall"
    "-Werror"
    "-Wextra"
    "-Wno-deprecated-pragma"
    "-Wno-missing-field-initializers"
)

set(libcutils_srcs
    "canned_fs_config.cpp"
    "fs_config.cpp"
)

list(TRANSFORM libcutils_srcs PREPEND "${TARGET_SRC_DIR}/")

add_library(${TARGET} STATIC ${libcutils_srcs})

target_include_directories(${TARGET} PUBLIC "${TARGET_SRC_DIR}/include")

target_link_libraries(${TARGET} PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,base_static,log_static>")

target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
