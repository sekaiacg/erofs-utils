set(TARGET packagelistparser)

set(TARGET_SRC_DIR "${MODULES_SRC}/core/libpackagelistparser")

set(LIBPACKAGELISTPARSER_SRCS "${TARGET_SRC_DIR}/packagelistparser.cpp")

add_library(${TARGET} STATIC ${LIBPACKAGELISTPARSER_SRCS})

target_include_directories(${TARGET} PRIVATE "${TARGET_SRC_DIR}/include")

target_link_libraries(${TARGET} log)
