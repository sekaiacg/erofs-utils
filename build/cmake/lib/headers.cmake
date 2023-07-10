# header
set(libcutils_headers             "${LIB_DIR}/core/libcutils/include"               CACHE INTERNAL "libcutils_headers")
set(libutils_headers              "${LIB_DIR}/core/libutils/include"                CACHE INTERNAL "libutils_headers")
set(libbase_headers               "${LIB_DIR}/libbase/include"                      CACHE INTERNAL "libbase_headers")
set(libsystem_headers             "${LIB_DIR}/core/libsystem/include"               CACHE INTERNAL "libsystem_headers")
set(liblog_headers                "${LIB_DIR}/logging/liblog/include"               CACHE INTERNAL "liblog_headers")
set(liblz4_headers                "${LIB_DIR}/lz4/lib"                              CACHE INTERNAL "liblz4_headers")
set(liblzma_headers               "${LIB_DIR}/xz/src/liblzma/api"                   CACHE INTERNAL "liblzma_headers")
set(libpcre2_headers              "${LIB_DIR}/pcre/include"                         CACHE INTERNAL "libpcre2_headers")
set(libselinux_headers            "${LIB_DIR}/selinux/libselinux/include"           CACHE INTERNAL "libselinux_headers")
set(libfuse_headers               "${LIB_DIR}/libfuse/include"                      CACHE INTERNAL "libfuse_headers")
set(liberofs_headers
	"${PROJECT_ROOT_DIR}/include"
	"${CMAKE_BINARY_DIR}"
	CACHE INTERNAL "liberofs_headers"
)
set(libpackagelistparser_headers  "${LIB_DIR}/core/libpackagelistparser/include"    CACHE INTERNAL "libpackagelistparser_headers")
set(libe2fsprogs_headers          "${LIB_DIR}/e2fsprogs/lib/uuid"                   CACHE INTERNAL "libe2fsprogs_headers")
