set(TARGET log)

add_library(${TARGET} STATIC
    ${SRC}/logging/liblog/log_event_list.cpp
    ${SRC}/logging/liblog/log_event_write.cpp
    ${SRC}/logging/liblog/logger_name.cpp
    ${SRC}/logging/liblog/logger_read.cpp
    ${SRC}/logging/liblog/logger_write.cpp
    ${SRC}/logging/liblog/properties.cpp
    ${SRC}/logging/liblog/logprint.cpp
    )

target_compile_definitions(${TARGET} PRIVATE
    -DLIBLOG_LOG_TAG=1006 
    -D_XOPEN_SOURCE=700 
    -DFAKE_LOG_DEVICE=1
    -DSNET_EVENT_LOG_TAG=1397638686
    )
    
target_include_directories(${TARGET} PUBLIC
    ${SRC}/core/include
    ${SRC}/logging/liblog/include
    ${SRC}/core/libcutils/include
    ${SRC}/libbase/include
    )