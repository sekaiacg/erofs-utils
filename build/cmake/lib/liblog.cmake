set(TARGET log)

set(TARGET_SRC_DIR "${LIB_DIR}/logging/liblog")

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

if (CYGWIN)
	# this is cygwin bug
	list(APPEND TARGET_CFLAGS "-D_Bool=bool")
endif()

set(liblog_srcs
	"${TARGET_SRC_DIR}/log_event_list.cpp"
	"${TARGET_SRC_DIR}/log_event_write.cpp"
	"${TARGET_SRC_DIR}/logger_name.cpp"
	"${TARGET_SRC_DIR}/logger_read.cpp"
	"${TARGET_SRC_DIR}/logger_write.cpp"
	"${TARGET_SRC_DIR}/logprint.cpp"
	"${TARGET_SRC_DIR}/properties.cpp"
)
set(liblog_targs_srcs
	"${TARGET_SRC_DIR}/event_tag_map.cpp"
	"${TARGET_SRC_DIR}/log_time.cpp"
	"${TARGET_SRC_DIR}/pmsg_reader.cpp"
	"${TARGET_SRC_DIR}/pmsg_writer.cpp"
	"${TARGET_SRC_DIR}/logd_reader.cpp"
	"${TARGET_SRC_DIR}/logd_writer.cpp"
)

if (CMAKE_SYSTEM_NAME MATCHES "Android")
	#list(APPEND liblog_srcs ${liblog_targs_srcs})
endif ()

add_library(${TARGET} STATIC ${liblog_srcs})

target_include_directories(${TARGET} PRIVATE
	${liblog_headers}
	${libcutils_headers}
	${libbase_headers}
)

target_compile_options(${TARGET} PRIVATE
	"$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
	"$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
