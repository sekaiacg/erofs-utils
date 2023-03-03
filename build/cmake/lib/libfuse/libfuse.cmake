set(TARGET fuse_static)

set(TARGET_SRC_DIR "${LIB_DIR}/libfuse/lib")

include(check.cmake)
include(CheckStructHasMember)
set(LIBFUSE_FUNC_LIST
	"copy_file_range"
	"fork"
	"fstatat"
	"openat"
	"readlinkat"
	"pipe2"
	"splice"
	"vmsplice"
	"posix_fallocate"
	"fdatasync"
	"utimensat"
	"fallocate"
)
check_fun(LIBFUSE_FUNC_LIST)
check_symbol_exists(setxattr "sys/xattr.h" HAVE_SETXATTR)
check_symbol_exists(iconv "iconv.h" HAVE_ICONV)
check_struct_has_member("struct stat" "st_atim" "sys/stat.h" HAVE_STRUCT_STAT_ST_ATIM)
check_struct_has_member("struct stat" "st_atimespec" "sys/stat.h" HAVE_STRUCT_STAT_ST_ATIMESPEC)
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/libfuse/fuse_config.h.in"
	"${libfuse_headers}/fuse_config.h"
)

set(LIBFUSE_DEFAULTS_CFLAGS
	"-DFUSE_USE_VERSION=314"
	"-D_REENTRANT"
	"-DHAVE_LIBFUSE_PRIVATE_CONFIG_H"
	"-Wall"
	"-Wextra"
	"-Wno-sign-compare"
	"-Wno-incompatible-pointer-types"
	"-Wno-missing-field-initializers"
	"-Wno-unused-result"
	"-Wno-implicit-function-declaration"
	"-Wno-unused-parameter"
	"-Wno-unused-variable"
	CACHE INTERNAL "libfuse_defaults_cflags"
)

set(libfuse_srcs
	"${TARGET_SRC_DIR}/buffer.c"
	"${TARGET_SRC_DIR}/cuse_lowlevel.c"
	"${TARGET_SRC_DIR}/fuse.c"
	"${TARGET_SRC_DIR}/fuse_log.c"
	"${TARGET_SRC_DIR}/fuse_loop.c"
	"${TARGET_SRC_DIR}/fuse_loop_mt.c"
	"${TARGET_SRC_DIR}/fuse_lowlevel.c"
	"${TARGET_SRC_DIR}/fuse_opt.c"
	"${TARGET_SRC_DIR}/fuse_signals.c"
	"${TARGET_SRC_DIR}/helper.c"
	"${TARGET_SRC_DIR}/modules/subdir.c"
	"${TARGET_SRC_DIR}/modules/iconv.c"
	"${TARGET_SRC_DIR}/mount.c"
	"${TARGET_SRC_DIR}/mount_util.c"
	"${TARGET_SRC_DIR}/compat.c"
)

file(GLOB LIBFUSE_CONFIG_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/libfuse/*.h")
file(COPY ${LIBFUSE_CONFIG_HEADER} DESTINATION ${libfuse_headers})

if (CMAKE_SYSTEM_NAME MATCHES "Linux|Darwin")
	list(APPEND LIBFUSE_DEFAULTS_CFLAGS "-DFUSERMOUNT_DIR=\"/bin\"")
elseif (CMAKE_SYSTEM_NAME MATCHES "Android")
	list(APPEND LIBFUSE_DEFAULTS_CFLAGS "-DFUSERMOUNT_DIR=\"/system/bin\"")
endif()

add_library(${TARGET} STATIC ${libfuse_srcs})

target_include_directories(${TARGET} PRIVATE
	${libfuse_headers}
	${TARGET_SRC_DIR}
)

target_compile_options(${TARGET} PRIVATE ${LIBFUSE_DEFAULTS_CFLAGS})
