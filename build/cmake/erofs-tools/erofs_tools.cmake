set(common_compile_flags
	"$<$<COMPILE_LANGUAGE:C>:${LIBEROFS_STATIC_DEFAULTS_CFLAGS}>"
	"$<$<COMPILE_LANGUAGE:CXX>:${LIBEROFS_STATIC_DEFAULTS_CFLAGS}>"
)

set(common_headers
	${liberofs_headers}
	${libcutils_headers}
	${libselinux_headers}
	${libe2fsprogs_headers}
)

if (CMAKE_SYSTEM_NAME MATCHES "Linux|Android")
	set(ld_start_group "-Wl,--start-group" "fuse_static")
	set(ld_end_group "-Wl,--end-group")
endif()

set(common_static_link_lib
	${ld_start_group}
	base
	cutils
	log
	selinux
	pcre2
	ext2_uuid
	lz4_static
	liblzma
	dl
	erofs_static
	${ld_end_group}
)

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
	file(GLOB fuse_srcs "${PROJECT_ROOT_DIR}/fuse/*.c")

	add_executable(${TARGET_fuse} ${fuse_srcs})
	target_precompile_headers(${TARGET_fuse} PRIVATE "${PROJECT_ROOT_DIR}/fuse/macosx.h")
	target_include_directories(${TARGET_fuse} PRIVATE ${common_headers} ${libfuse_headers})
	target_link_libraries(${TARGET_fuse} ${common_static_link_lib})
	target_compile_options(${TARGET_fuse} PRIVATE
		${common_compile_flags}
		"$<$<COMPILE_LANGUAGE:C>:${LIBFUSE_DEFAULTS_CFLAGS}>"
		"$<$<COMPILE_LANGUAGE:CXX>:${LIBFUSE_DEFAULTS_CFLAGS}>"
	)
##################################################################################
endif()
