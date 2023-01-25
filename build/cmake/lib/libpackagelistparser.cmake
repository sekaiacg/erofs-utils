set(TARGET packagelistparser)

set(TARGET_SRC_DIR "${LIB_DIR}/core/libpackagelistparser")

set(libpackagelistparser_srcs "${TARGET_SRC_DIR}/packagelistparser.cpp")

add_library(${TARGET} STATIC ${libpackagelistparser_srcs})

target_include_directories(${TARGET} PRIVATE
	${libpackagelistparser_headers}
	${liblog_headers}
)
