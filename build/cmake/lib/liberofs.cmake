set(TARGET erofs_static)

set(TARGET_SRC_DIR "${PROJECT_ROOT_DIR}/lib")

# Check function and header
include(check.cmake)
set(liberofs_include_list
	"execinfo.h"
	"linux/falloc.h"
	"linux/fs.h"
	"linux/types.h"
	"linux/xattr.h"
	"sys/ioctl.h"
	"sys/sysmacros.h"
)

set(liberofs_function_list
	"backtrace"
	"utimensat"
)
if (CMAKE_SYSTEM_NAME MATCHES "Linux|Android")
	list(APPEND liberofs_include_list
		"sys/random.h"
	)
	list(APPEND liberofs_function_list
		"copy_file_range"
		"fallocate"
		"ftello64"
		"lseek64"
		"memrchr"
		"pread64"
		"pwrite64"
		"tmpfile64"
	)
	if (NOT RUN_ON_WSL)
		list(APPEND liberofs_function_list
			"lgetxattr"
			"llistxattr"
		)
	endif ()
elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
	set(DARWIN_CFLAGS "-DHAVE_LIBUUID")
endif ()
check_include(liberofs_include_list)
check_fun(liberofs_function_list)
check_symbol_exists(lseek64 "unistd.h" HAVE_LSEEK64_PROTOTYPE)
check_symbol_exists(TIOCGWINSZ "sys/ioctl.h" GWINSZ_IN_SYS_IOCTL)
check_struct_has_member("struct stat" "st_atim" "sys/stat.h" HAVE_STRUCT_STAT_ST_ATIM)
check_struct_has_member("struct stat" "st_atimespec" "sys/stat.h" HAVE_STRUCT_STAT_ST_ATIMESPEC)
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/liberofs_config.h.in"
	"${CMAKE_BINARY_DIR}/config.h"
)

set(LIBEROFS_STATIC_DEFAULTS_CFLAGS
	"-Wall"
	"-Wno-ignored-qualifiers"
	"-Wno-pointer-arith"
	"-Wno-unused-parameter"
	"-Wno-unused-function"
	"-Wno-deprecated-declarations"
	"-DHAVE_LIBSELINUX"
	"-DLZ4_ENABLED"
	"-DLZ4HC_ENABLED"
	"-DHAVE_ZLIB"
	"-DHAVE_LIBLZMA"
	"-DWITH_ANDROID"
	"${DARWIN_CFLAGS}"
	CACHE INTERNAL "liberofs_static_defaults_cflags"
)

set(liberofs_srcs
	"${TARGET_SRC_DIR}/config.c"
	"${TARGET_SRC_DIR}/io.c"
	"${TARGET_SRC_DIR}/cache.c"
	"${TARGET_SRC_DIR}/super.c"
	"${TARGET_SRC_DIR}/inode.c"
	"${TARGET_SRC_DIR}/xattr.c"
	"${TARGET_SRC_DIR}/exclude.c"
	"${TARGET_SRC_DIR}/namei.c"
	"${TARGET_SRC_DIR}/data.c"
	"${TARGET_SRC_DIR}/compress.c"
	"${TARGET_SRC_DIR}/compressor.c"
	"${TARGET_SRC_DIR}/zmap.c"
	"${TARGET_SRC_DIR}/decompress.c"
	"${TARGET_SRC_DIR}/compress_hints.c"
	"${TARGET_SRC_DIR}/hashmap.c"
	"${TARGET_SRC_DIR}/sha256.c"
	"${TARGET_SRC_DIR}/blobchunk.c"
	"${TARGET_SRC_DIR}/dir.c"
	"${TARGET_SRC_DIR}/block_list.c"
	"${TARGET_SRC_DIR}/fragments.c"
	"${TARGET_SRC_DIR}/rb_tree.c"
	"${TARGET_SRC_DIR}/dedupe.c"
	"${TARGET_SRC_DIR}/uuid.c"
	"${TARGET_SRC_DIR}/tar.c"
	"${TARGET_SRC_DIR}/uuid_unparse.c"
	"${TARGET_SRC_DIR}/compressor_lz4.c"
	"${TARGET_SRC_DIR}/compressor_lz4hc.c"
	"${TARGET_SRC_DIR}/compressor_liblzma.c"
	"${TARGET_SRC_DIR}/kite_deflate.c"
	"${TARGET_SRC_DIR}/compressor_deflate.c"
)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-Wno-deprecated-non-prototype" CFLAG_Wno-deprecated-non-prototype)
if (CFLAG_Wno-deprecated-non-prototype)
	list(APPEND LIBEROFS_STATIC_DEFAULTS_CFLAGS "-Wno-deprecated-non-prototype")
endif()

add_library(${TARGET} STATIC ${liberofs_srcs})

target_precompile_headers(${TARGET} PRIVATE "${CMAKE_BINARY_DIR}/erofs-utils-version.h")
target_precompile_headers(${TARGET} PUBLIC "${CMAKE_BINARY_DIR}/config.h")

target_include_directories(${TARGET} PRIVATE
	${liberofs_headers}
	${libcutils_headers}
	${libselinux_headers}
	${liblz4_headers}
	${liblzma_headers}
	${libz_headers}
	${libpcre2_headers}
	${libe2fsprogs_headers}
)

target_compile_options(${TARGET} PRIVATE
	"$<$<COMPILE_LANGUAGE:C>:${LIBEROFS_STATIC_DEFAULTS_CFLAGS}>"
	"$<$<COMPILE_LANGUAGE:CXX>:${LIBEROFS_STATIC_DEFAULTS_CFLAGS}>"
)
