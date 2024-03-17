set(common_compile_flags
	"$<$<COMPILE_LANGUAGE:C>:${LIBEROFS_STATIC_DEFAULTS_CFLAGS}>"
	"$<$<COMPILE_LANGUAGE:CXX>:${LIBEROFS_STATIC_DEFAULTS_CFLAGS}>"
)

set(common_headers
	${liberofs_headers}
	${libcutils_headers}
	${libselinux_headers}
	${libe2fsprogs_headers}
	${liblz4_headers}
	${liblzma_headers}
	${libz_headers}
)

if (CMAKE_SYSTEM_NAME MATCHES "Linux|Android")
	set(ld_start_group "-Wl,--start-group" "fuse_static")
	set(ld_end_group "-Wl,--end-group")
endif()

set(common_static_link_lib
	${ld_start_group}
	dl
	erofs_static
	cutils
	base
	log
	selinux
	lz4_static
	liblzma
	z_stable
	pcre2
	${ld_end_group}
)

if (CMAKE_SYSTEM_NAME MATCHES "Darwin|CYGWIN")
	list(APPEND common_static_link_lib "ext2_uuid" "iconv")
endif()

if (CYGWIN)
	# extract.erofs use ntdll function to change a dir case sensitive
	# so we need to link to ntdll
	list(APPEND common_static_link_lib "ntdll")
endif ()

###############################------mkfs.erofs------###############################
set(TARGET_mkfs mkfs.erofs)
file(GLOB mkfs_srcs "${PROJECT_ROOT_DIR}/mkfs/*.c")
add_executable(${TARGET_mkfs} ${mkfs_srcs})
target_include_directories(${TARGET_mkfs} PRIVATE ${common_headers})
target_link_libraries(${TARGET_mkfs} ${common_static_link_lib})
target_compile_options(${TARGET_mkfs} PRIVATE ${common_compile_flags})
##################################################################################

###############################------dump.erofs------###############################
set(TARGET_dump dump.erofs)
file(GLOB dump_srcs "${PROJECT_ROOT_DIR}/dump/*.c")
add_executable(${TARGET_dump} ${dump_srcs})
target_include_directories(${TARGET_dump} PRIVATE ${common_headers})
target_link_libraries(${TARGET_dump} ${common_static_link_lib})
target_compile_options(${TARGET_dump} PRIVATE ${common_compile_flags})

###############################------fsck.erofs------###############################
set(TARGET_fsck fsck.erofs)
file(GLOB fsck_srcs "${PROJECT_ROOT_DIR}/fsck/*.c")
add_executable(${TARGET_fsck} ${fsck_srcs})
target_include_directories(${TARGET_fsck} PRIVATE ${common_headers})
target_link_libraries(${TARGET_fsck} ${common_static_link_lib})
target_compile_options(${TARGET_fsck} PRIVATE ${common_compile_flags})
##################################################################################

if (CMAKE_SYSTEM_NAME MATCHES "Linux|Android")
###############################------fuse.erofs------###############################
	set(TARGET_fuse fuse.erofs)
	set(fuse_srcs "${PROJECT_ROOT_DIR}/fuse/main.c")

	add_executable(${TARGET_fuse} ${fuse_srcs})
	target_precompile_headers(${TARGET_fuse} PRIVATE
		"${PROJECT_ROOT_DIR}/fuse/macosx.h"
		"${LIB_DIR}/libfuse/lib/fuse_i.h"
	)

	target_include_directories(${TARGET_fuse} PRIVATE ${common_headers} ${libfuse_headers})
	target_link_libraries(${TARGET_fuse} ${common_static_link_lib})
	target_compile_options(${TARGET_fuse} PRIVATE
		${common_compile_flags}
		"$<$<COMPILE_LANGUAGE:C>:${LIBFUSE_DEFAULTS_CFLAGS}>"
		"$<$<COMPILE_LANGUAGE:CXX>:${LIBFUSE_DEFAULTS_CFLAGS}>"
	)
elseif (CYGWIN)
	# use winfsp instead libfuse
	# install winfsp to cygwin
	execute_process(COMMAND bash "${LIB_DIR}/winfsp/opt/cygfuse/dist/install.sh")
	set(TARGET_fuse fuse.erofs)
	set(fuse_srcs "${PROJECT_ROOT_DIR}/fuse/main_win.c")

	add_executable(${TARGET_fuse} ${fuse_srcs})
	target_include_directories(${TARGET_fuse} PRIVATE ${common_headers} "/usr/include/fuse")
	target_link_libraries(${TARGET_fuse} ${common_static_link_lib} "/usr/lib/libfuse-2.8.dll.a" "${LIB_DIR}/winfsp-x64.dll")
	target_compile_options(${TARGET_fuse} PRIVATE
		${common_compile_flags}
		"$<$<COMPILE_LANGUAGE:C>:${LIBFUSE_DEFAULTS_CFLAGS}>"
		"$<$<COMPILE_LANGUAGE:CXX>:${LIBFUSE_DEFAULTS_CFLAGS}>"
	)
##################################################################################
endif()
