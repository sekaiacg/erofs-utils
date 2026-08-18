set(TARGET z_static)

set(TARGET_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/zlib")
set(LIBZ_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/zlib")

set(TARGET_CFLAGS
    "-DHAVE_HIDDEN"
    "-DZLIB_CONST"
    "-DCHROMIUM_ZLIB_NO_CASTAGNOLI"
    "-O3"
    "-Wall"
    "-Werror"
    "-Wno-deprecated-non-prototype"
    "-Wno-unused"
    "-Wno-unused-parameter"
)

set(cflags_lp64
    "-DDEFLATE_CHUNK_WRITE_64LE"
    "-DINFLATE_CHUNK_READ_64LE"
)
set(cflags_arm
    "-DADLER32_SIMD_NEON"
    "-DDEFLATE_SLIDE_HASH_NEON"
    "-DINFLATE_CHUNK_SIMD_NEON"
    "-DCRC32_ARMV8_CRC32"
)
set(cflags_arm64 ${cflags_arm} ${cflags_lp64})
set(cflags_riscv64
    "-DRISCV_RVV"
    "-DADLER32_SIMD_RVV"
    "-DDEFLATE_SLIDE_HASH_RVV"
    "-DINFLATE_CHUNK_GENERIC"
    ${cflags_lp64}
)
set(cflags_x86
    "-DADLER32_SIMD_SSSE3"
    "-DDEFLATE_SLIDE_HASH_SSE2"
    "-DINFLATE_CHUNK_SIMD_SSE2"
    "-DCRC32_SIMD_SSE42_PCLMUL"
)
set(cflags_x86_64 ${cflags_x86} ${cflags_lp64})

set(libz_srcs
    "adler32.c"
    "adler32_simd.c"
    "compress.c"
    "cpu_features.c"
    "crc32.c"
    "crc32_simd.c"
    "crc_folding.c"
    "deflate.c"
    "gzclose.c"
    "gzlib.c"
    "gzread.c"
    "gzwrite.c"
    "infback.c"
    "inffast.c"
    "inftrees.c"
    "trees.c"
    "uncompr.c"
    "zutil.c"
    "contrib/optimizations/inffast_chunk.c"
    "contrib/optimizations/inflate.c"
)

# Similarly, we don't want optimizations.
if (USE_LIBZ_STABLE_VERSION OR CMAKE_SYSTEM_PROCESSOR MATCHES "loongarch64|riscv64")
    list(REMOVE_ITEM libz_srcs
        "contrib/optimizations/inffast_chunk.c"
        "contrib/optimizations/inflate.c"
    )
    list(APPEND libz_srcs "inflate.c")
endif ()

list(TRANSFORM libz_srcs PREPEND "${TARGET_SRC_DIR}/")

add_library(${TARGET} STATIC ${libz_srcs})

set_target_properties(${TARGET} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${LIBZ_BINARY_DIR})

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "arm" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7-a")
    list(APPEND TARGET_CFLAGS ${cflags_arm})
    if (CMAKE_SYSTEM_NAME MATCHES "Android|Linux|CYGWIN")
        list(APPEND TARGET_CFLAGS "-DARMV8_OS_LINUX")
    elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
        list(APPEND TARGET_CFLAGS "-DARMV8_OS_WINDOWS")
    endif ()
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    list(APPEND TARGET_CFLAGS ${cflags_arm64})
    if (CMAKE_SYSTEM_NAME MATCHES "Android|Linux|CYGWIN")
        list(APPEND TARGET_CFLAGS "-DARMV8_OS_LINUX")
    elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        list(APPEND TARGET_CFLAGS "-DARMV8_OS_MACOS")
    elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
        list(APPEND TARGET_CFLAGS "-DARMV8_OS_WINDOWS")
    endif ()
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
    list(APPEND TARGET_CFLAGS ${cflags_riscv64})
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "i686" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    list(APPEND TARGET_CFLAGS ${cflags_x86})
    if (CMAKE_SYSTEM_NAME MATCHES "Android|Linux|CYGWIN")
        list(APPEND TARGET_CFLAGS "-DX86_NOT_WINDOWS")
    elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
        list(APPEND TARGET_CFLAGS "-DX86_WINDOWS")
    endif ()
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    list(APPEND TARGET_CFLAGS ${cflags_x86_64})
    if (CMAKE_SYSTEM_NAME MATCHES "Android|Linux|Darwin|CYGWIN")
        list(APPEND TARGET_CFLAGS "-DX86_NOT_WINDOWS")
    elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
        list(APPEND TARGET_CFLAGS "-DX86_WINDOWS")
    endif ()
endif ()

target_include_directories(${TARGET} PUBLIC ${TARGET_SRC_DIR})

if (CMAKE_SYSTEM_PROCESSOR MATCHES "i686|x86_64|x86")
    list(APPEND TARGET_CFLAGS "-msse4.2" "-mpclmul")
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    list(APPEND TARGET_CFLAGS "-march=armv8-a+crypto")
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "armv7-a")
    list(APPEND TARGET_CFLAGS "-march=armv7-a")
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Windows|CYGWIN")
    target_link_libraries(${TARGET} PUBLIC "$<LINK_LIBRARY:WHOLE_ARCHIVE,pthread>")
endif ()

target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
