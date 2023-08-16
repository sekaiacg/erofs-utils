set(TARGET z_stable)

set(TARGET_SRC_DIR "${LIB_DIR}/zlib")

set(TARGET_CFLAGS
	"-DHAVE_HIDDEN"
	"-DZLIB_CONST"
	"-O3"
	"-Wall"
	"-Werror"
	"-Wno-unused"
	"-Wno-unused-parameter"
)

set(libz_srcs
	"${TARGET_SRC_DIR}/adler32.c"
	"${TARGET_SRC_DIR}/adler32_simd.c"
	"${TARGET_SRC_DIR}/compress.c"
	"${TARGET_SRC_DIR}/cpu_features.c"
	"${TARGET_SRC_DIR}/crc32.c"
	"${TARGET_SRC_DIR}/crc32_simd.c"
	"${TARGET_SRC_DIR}/crc_folding.c"
	"${TARGET_SRC_DIR}/deflate.c"
	"${TARGET_SRC_DIR}/gzclose.c"
	"${TARGET_SRC_DIR}/gzlib.c"
	"${TARGET_SRC_DIR}/gzread.c"
	"${TARGET_SRC_DIR}/gzwrite.c"
	"${TARGET_SRC_DIR}/infback.c"
	"${TARGET_SRC_DIR}/inffast.c"
	"${TARGET_SRC_DIR}/inflate.c"
	"${TARGET_SRC_DIR}/inftrees.c"
	"${TARGET_SRC_DIR}/trees.c"
	"${TARGET_SRC_DIR}/uncompr.c"
	"${TARGET_SRC_DIR}/zutil.c"
)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-Wno-deprecated-non-prototype" CFLAG_Wno-deprecated-non-prototype)
if (CFLAG_Wno-deprecated-non-prototype)
	list(APPEND TARGET_CFLAGS "-Wno-deprecated-non-prototype")
endif ()

set(cflags_arm "-O3" "-DADLER32_SIMD_NEON" "-DCRC32_ARMV8_CRC32")
set(cflags_arm64 ${cflags_arm})
set(cflags_x86 "-DX86_NOT_WINDOWS" "-DCPU_NO_SIMD")
set(cflags_android_x86 "-UCPU_NO_SIMD" "-DADLER32_SIMD_SSSE3")
set(cflags_64 "-DINFLATE_CHUNK_READ_64LE")

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
	list(APPEND TARGET_CFLAGS ${cflags_arm64} ${cflags_64})
	if (CMAKE_SYSTEM_NAME MATCHES "Linux|Android")
		list(APPEND TARGET_CFLAGS "-DARMV8_OS_LINUX")
	elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
		list(APPEND TARGET_CFLAGS "-DARMV8_OS_MACOS")
	endif ()
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "arm|armv7-a")
	list(APPEND TARGET_CFLAGS ${cflags_arm})
	if (CMAKE_SYSTEM_NAME STREQUAL "Android")
		list(APPEND TARGET_CFLAGS "-DARMV8_OS_LINUX")
	endif ()
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
	list(APPEND TARGET_CFLAGS ${cflags_x86} ${cflags_64})
	if (CMAKE_SYSTEM_NAME STREQUAL "Android")
		list(APPEND TARGET_CFLAGS ${cflags_android_x86})
	endif ()
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
	list(APPEND TARGET_CFLAGS ${cflags_x86})
	if (CMAKE_SYSTEM_NAME STREQUAL "Android")
		list(APPEND TARGET_CFLAGS ${cflags_android_x86})
	endif ()
endif ()

add_library(${TARGET} STATIC ${libz_srcs})

target_include_directories(${TARGET} PRIVATE ${libz_headers})

target_compile_options(${TARGET} PRIVATE
	"$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
	"$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
