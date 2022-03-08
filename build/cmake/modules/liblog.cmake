set(TARGET log)

set(TARGET_SRC_DIR "${MODULES_SRC}/logging/liblog")

set(TARGET_CFLAGS
    "-Wall"
    "-Wextra"
    "-Wexit-time-destructors"
    "-DLIBLOG_LOG_TAG=1006"
    "-DSNET_EVENT_LOG_TAG=1397638484"
)

set(LIBLOG_SRCS
    "${TARGET_SRC_DIR}/log_event_list.cpp"
    "${TARGET_SRC_DIR}/log_event_write.cpp"
    "${TARGET_SRC_DIR}/logger_name.cpp"
    "${TARGET_SRC_DIR}/logger_read.cpp"
    "${TARGET_SRC_DIR}/logger_write.cpp"
    "${TARGET_SRC_DIR}/logprint.cpp"
    "${TARGET_SRC_DIR}/properties.cpp"
)
set(LIBLOG_TARGET_SRCS
    "${TARGET_SRC_DIR}/event_tag_map.cpp"
    "${TARGET_SRC_DIR}/log_time.cpp"
    "${TARGET_SRC_DIR}/pmsg_reader.cpp"
    "${TARGET_SRC_DIR}/pmsg_writer.cpp"
    "${TARGET_SRC_DIR}/logd_reader.cpp"
    "${TARGET_SRC_DIR}/logd_writer.cpp"
)

if (CMAKE_SYSTEM_NAME MATCHES "Android")
    list(APPEND LIBLOG_SRCS ${LIBLOG_TARGET_SRCS})
endif()

add_library(${TARGET} STATIC ${LIBLOG_SRCS})

target_include_directories(${TARGET} PRIVATE
    "${TARGET_SRC_DIR}/include"
    "${MODULES_SRC}/core/include"
    "${MODULES_SRC}/core/libcutils/include"
    "${MODULES_SRC}/libbase/include"
)

target_compile_options(${TARGET} PRIVATE ${TARGET_CFLAGS})
