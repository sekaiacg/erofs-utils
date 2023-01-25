set(TARGET cutils)

set(TARGET_SRC_DIR "${LIB_DIR}/core/libcutils")

set(TARGET_CFLAGS
	"-Wno-exit-time-destructors"
	"-Wall"
	"-Werror"
	"-Wextra"
	"-Wno-deprecated-pragma"
)

set(libcutils_srcs
	"${TARGET_SRC_DIR}/config_utils.cpp"
	"${TARGET_SRC_DIR}/iosched_policy.cpp"
	"${TARGET_SRC_DIR}/load_file.cpp"
	"${TARGET_SRC_DIR}/native_handle.cpp"
	"${TARGET_SRC_DIR}/properties.cpp"
	"${TARGET_SRC_DIR}/record_stream.cpp"
	"${TARGET_SRC_DIR}/strlcpy.c"
	"${TARGET_SRC_DIR}/threads.cpp"
)
set(libcutils_nonwindows_srcs
	"${TARGET_SRC_DIR}/fs.cpp"
	"${TARGET_SRC_DIR}/hashmap.cpp"
	"${TARGET_SRC_DIR}/multiuser.cpp"
	"${TARGET_SRC_DIR}/str_parms.cpp"
)

set(libcutils_socket_srcs
	"${TARGET_SRC_DIR}/sockets.cpp"
)
set(libcutils_socket_nonwindows_srcs
	"${TARGET_SRC_DIR}/socket_inaddr_any_server_unix.cpp"
	"${TARGET_SRC_DIR}/socket_local_client_unix.cpp"
	"${TARGET_SRC_DIR}/socket_local_server_unix.cpp"
	"${TARGET_SRC_DIR}/socket_network_client_unix.cpp"
	"${TARGET_SRC_DIR}/sockets_unix.cpp"
)

if (CMAKE_SYSTEM_NAME MATCHES "Linux|Darwin")
	list(APPEND libcutils_srcs
		${libcutils_socket_srcs}
		${libcutils_socket_nonwindows_srcs}
		${libcutils_nonwindows_srcs}
		"${TARGET_SRC_DIR}/ashmem-host.cpp"
		"${TARGET_SRC_DIR}/canned_fs_config.cpp"
		"${TARGET_SRC_DIR}/fs_config.cpp"
		"${TARGET_SRC_DIR}/trace-host.cpp"
	)
elseif (CMAKE_SYSTEM_NAME MATCHES "Android")
	list(APPEND libcutils_socket_srcs
		"${TARGET_SRC_DIR}/android_get_control_file.cpp"
		"${TARGET_SRC_DIR}/socket_inaddr_any_server_unix.cpp"
		"${TARGET_SRC_DIR}/socket_local_client_unix.cpp"
		"${TARGET_SRC_DIR}/socket_local_server_unix.cpp"
		"${TARGET_SRC_DIR}/socket_network_client_unix.cpp"
		"${TARGET_SRC_DIR}/sockets_unix.cpp"
	)
	list(APPEND libcutils_srcs
		${libcutils_socket_srcs}
		${libcutils_socket_nonwindows_srcs}
		${libcutils_nonwindows_srcs}
		"${TARGET_SRC_DIR}/android_reboot.cpp"
		"${TARGET_SRC_DIR}/ashmem-dev.cpp"
		"${TARGET_SRC_DIR}/canned_fs_config.cpp"
		"${TARGET_SRC_DIR}/fs_config.cpp"
		"${TARGET_SRC_DIR}/klog.cpp"
		"${TARGET_SRC_DIR}/partition_utils.cpp"
		"${TARGET_SRC_DIR}/qtaguid.cpp"
		"${TARGET_SRC_DIR}/trace-dev.cpp"
		"${TARGET_SRC_DIR}/uevent.cpp"
	)
endif()

add_library(${TARGET} STATIC ${libcutils_srcs})

target_include_directories(${TARGET} PRIVATE
	${libcutils_headers}
	${libbase_headers}
	${libutils_headers}
	${liblog_headers}
)

target_compile_options(${TARGET} PRIVATE
	"$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
	"$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
