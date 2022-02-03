set(TARGET cutils)

add_library(${TARGET} STATIC
    ${SRC}/core/libcutils/android_get_control_file.cpp
    ${SRC}/core/libcutils/ashmem-host.cpp
    ${SRC}/core/libcutils/canned_fs_config.cpp
    ${SRC}/core/libcutils/config_utils.cpp
    ${SRC}/core/libcutils/fs.cpp
    ${SRC}/core/libcutils/fs_config.cpp
    ${SRC}/core/libcutils/hashmap.cpp
    ${SRC}/core/libcutils/iosched_policy.cpp
    ${SRC}/core/libcutils/load_file.cpp
    ${SRC}/core/libcutils/multiuser.cpp
    ${SRC}/core/libcutils/native_handle.cpp
    ${SRC}/core/libcutils/properties.cpp
    ${SRC}/core/libcutils/record_stream.cpp
    ${SRC}/core/libcutils/socket_inaddr_any_server_unix.cpp
    ${SRC}/core/libcutils/socket_local_client_unix.cpp
    ${SRC}/core/libcutils/socket_local_server_unix.cpp
    ${SRC}/core/libcutils/socket_network_client_unix.cpp
    ${SRC}/core/libcutils/sockets_unix.cpp
    ${SRC}/core/libcutils/sockets.cpp
    ${SRC}/core/libcutils/str_parms.cpp
    ${SRC}/core/libcutils/strlcpy.c
    ${SRC}/core/libcutils/trace-host.cpp
    ${SRC}/core/libcutils/threads.cpp)

target_compile_definitions(${TARGET} PRIVATE -D_GNU_SOURCE)

target_include_directories(${TARGET} PUBLIC
    ${SRC}/core/libutils/include
    ${SRC}/core/libcutils/include
    ${SRC}/logging/liblog/include 
    ${SRC}/libbase/include
    )
    
