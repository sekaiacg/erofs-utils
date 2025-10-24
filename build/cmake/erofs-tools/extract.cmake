###############################------extract.erofs------###############################
set(TARGET_extract extract.erofs)
set(TARGET_SRC_DIR "${PROJECT_ROOT_DIR}/extract")
file(GLOB extract_srcs "${TARGET_SRC_DIR}/*.cpp")
add_executable(${TARGET_extract} ${extract_srcs})
target_include_directories(${TARGET_extract} PRIVATE
        "${TARGET_SRC_DIR}/include"
        ${common_headers}
)
target_link_libraries(${TARGET_extract} ${common_static_link_lib})
target_compile_options(${TARGET_extract} PRIVATE ${common_compile_flags} "-Wno-unused-result")

set(ENV{TZ} UTF-8)
execute_process(
	COMMAND date "+%y%m%d%H%M"
	OUTPUT_VARIABLE EXTRACT_BUILD_TIME
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
target_compile_definitions(${TARGET_extract} PRIVATE "-DEXTRACT_BUILD_TIME=\"-${EXTRACT_BUILD_TIME}\"")
MESSAGE(STATUS "[extract] build time is ${EXTRACT_BUILD_TIME}")
