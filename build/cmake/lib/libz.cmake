set(TARGET z_static)

set(TARGET_SRC_DIR "${LIB_DIR}/zlib")

set(TARGET_CFLAGS
	"-DHAVE_HIDDEN"
	"-DZLIB_CONST"
	"-DCHROMIUM_ZLIB_NO_CASTAGNOLI"
	"-O3"
	"-Wall"
	"-Werror"
	"-Wno-unused"
	"-Wno-unused-parameter"
)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-Wno-deprecated-non-prototype" CFLAG_Wno-deprecated-non-prototype)
if (CFLAG_Wno-deprecated-non-prototype)
	list(APPEND TARGET_CFLAGS "-Wno-deprecated-non-prototype")
endif ()

set(cflags_arm
	"-DINFLATE_CHUNK_SIMD_NEON"
	"-DADLER32_SIMD_NEON"
	"-DCRC32_ARMV8_CRC32"
	"-DDEFLATE_SLIDE_HASH_NEON"
)
set(cflags_arm64 ${cflags_arm} "-DINFLATE_CHUNK_READ_64LE")
set(cflags_riscv64
	"-DRISCV_RVV"
	"-DADLER32_SIMD_RVV"
	"-DDEFLATE_SLIDE_HASH_RVV"
	"-DINFLATE_CHUNK_GENERIC"
	"-DINFLATE_CHUNK_READ_64LE"
)
set(cflags_x86
	"-DX86_NOT_WINDOWS"
	"-DINFLATE_CHUNK_SIMD_SSE2"
	"-DADLER32_SIMD_SSSE3"
	"-DDEFLATE_SLIDE_HASH_SSE2"
	"-DCRC32_SIMD_SSE42_PCLMUL"
)
set(cflags_x86_64
	${cflags_x86}
	"-DDINFLATE_CHUNK_READ_64LE"
)
set(cflags_android_x86 "-DADLER32_SIMD_SSSE3")

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
add_library(${TARGET} STATIC ${libz_srcs})

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "arm" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7-a")
	list(APPEND TARGET_CFLAGS ${cflags_arm})
	if (CMAKE_SYSTEM_NAME STREQUAL "Android")
		list(APPEND TARGET_CFLAGS "-DARMV8_OS_LINUX")
	elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
		list(APPEND TARGET_CFLAGS "-DARMV8_OS_WINDOWS")
	endif ()
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
	list(APPEND TARGET_CFLAGS ${cflags_arm64})
	if (CMAKE_SYSTEM_NAME MATCHES "Android|Linux")
		list(APPEND TARGET_CFLAGS "-DARMV8_OS_LINUX")
	elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
		list(APPEND TARGET_CFLAGS "-DARMV8_OS_MACOS")
	elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
		list(APPEND TARGET_CFLAGS "-DARMV8_OS_WINDOWS")
	endif ()
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
	list(APPEND TARGET_CFLAGS ${cflags_riscv64})
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "i686")
	list(APPEND TARGET_CFLAGS ${cflags_x86})
	if (CMAKE_SYSTEM_NAME STREQUAL "Android")
		list(APPEND TARGET_CFLAGS ${cflags_android_x86})
	endif ()
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
	list(APPEND TARGET_CFLAGS ${cflags_x86_64})
	if (CMAKE_SYSTEM_NAME STREQUAL "Android")
		list(APPEND TARGET_CFLAGS ${cflags_android_x86})
	endif ()
endif ()

target_include_directories(${TARGET} PUBLIC ${TARGET_SRC_DIR})

if (CMAKE_SYSTEM_PROCESSOR MATCHES "i686|x86_64")
	target_compile_options(${TARGET} PRIVATE "-msse4.2" "-mpclmul")
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Windows|CYGWIN")
	target_link_libraries(${TARGET} "pthread")
endif ()

target_compile_options(${TARGET} PRIVATE
	"$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
	"$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
