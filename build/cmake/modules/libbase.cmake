set(TARGET base)

set(TARGET_SRC_DIR "${MODULES_SRC}/libbase")

set(TARGET_CFLAGS
    "-Wall"
    "-Werror"
    "-Wextra"
    "-Wexit-time-destructors"
)

set(LIBBASE_SRCS
    "${TARGET_SRC_DIR}/abi_compatibility.cpp"
    "${TARGET_SRC_DIR}/chrono_utils.cpp"
    "${TARGET_SRC_DIR}/cmsg.cpp"
    "${TARGET_SRC_DIR}/file.cpp"
    "${TARGET_SRC_DIR}/hex.cpp"
    "${TARGET_SRC_DIR}/logging.cpp"
    "${TARGET_SRC_DIR}/mapped_file.cpp"
    "${TARGET_SRC_DIR}/parsebool.cpp"
    "${TARGET_SRC_DIR}/parsenetaddress.cpp"
    "${TARGET_SRC_DIR}/posix_strerror_r.cpp"
    "${TARGET_SRC_DIR}/process.cpp"
    "${TARGET_SRC_DIR}/properties.cpp"
    "${TARGET_SRC_DIR}/stringprintf.cpp"
    "${TARGET_SRC_DIR}/strings.cpp"
    "${TARGET_SRC_DIR}/threads.cpp"
    "${TARGET_SRC_DIR}/test_utils.cpp"
)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    list(APPEND LIBBASE_SRCS "${TARGET_SRC_DIR}/errors_unix.cpp" )
elseif (CMAKE_SYSTEM_NAME MATCHES "Android")
    list(APPEND TARGET_CFLAGS
        "-D_FILE_OFFSET_BITS=64"
    )
endif()

add_library(${TARGET} STATIC ${LIBBASE_SRCS})

target_include_directories(${TARGET} PRIVATE
    "${TARGET_SRC_DIR}/include"
    "${MODULES_SRC}/core/include"
)

target_compile_options(${TARGET} PRIVATE $<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}> $<$<COMPILE_LANGUAGE:CXX>:${TARGET_CPPFLAGS}>)

target_link_libraries(${TARGET} log)
