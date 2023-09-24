set(TARGET selinux)

set(TARGET_SRC_DIR "${MODULES_SRC}/selinux/libselinux/src")

set(TARGET_CFLAGS
    "-DNO_PERSISTENTLY_STORED_PATTERNS"
    "-DDISABLE_SETRANS"
    "-DDISABLE_BOOL"
    "-D_GNU_SOURCE"
    "-DNO_MEDIA_BACKEND"
    "-DNO_X_BACKEND"
    "-DNO_DB_BACKEND"
    "-Wno-error=missing-noreturn"
    "-Wno-error=unused-function"
    "-Wno-error=unused-variable"
    "-DUSE_PCRE2"
)

set(LIBSELINUX_DEFAULTS_SRCS
    "${TARGET_SRC_DIR}/booleans.c"
    "${TARGET_SRC_DIR}/callbacks.c"
    "${TARGET_SRC_DIR}/freecon.c"
    "${TARGET_SRC_DIR}/label_backends_android.c"
    "${TARGET_SRC_DIR}/label.c"
    "${TARGET_SRC_DIR}/label_support.c"
    "${TARGET_SRC_DIR}/matchpathcon.c"
    "${TARGET_SRC_DIR}/setrans_client.c"
    "${TARGET_SRC_DIR}/sha1.c"
)

set(LIBSELINUX_SRCS
    "${TARGET_SRC_DIR}/label_file.c"
    "${TARGET_SRC_DIR}/regex.c"
)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    #linux_glibc
    list(APPEND LIBSELINUX_SRCS
        ${LIBSELINUX_DEFAULTS_SRCS}
        "${TARGET_SRC_DIR}/android/android_host.c"
        "${TARGET_SRC_DIR}/avc.c"
        "${TARGET_SRC_DIR}/avc_internal.c"
        "${TARGET_SRC_DIR}/avc_sidtab.c"
        "${TARGET_SRC_DIR}/compute_av.c"
        "${TARGET_SRC_DIR}/compute_create.c"
        "${TARGET_SRC_DIR}/compute_member.c"
        "${TARGET_SRC_DIR}/context.c"
        "${TARGET_SRC_DIR}/deny_unknown.c"
        "${TARGET_SRC_DIR}/enabled.c"
        "${TARGET_SRC_DIR}/fgetfilecon.c"
        "${TARGET_SRC_DIR}/getenforce.c"
        "${TARGET_SRC_DIR}/getfilecon.c"
        "${TARGET_SRC_DIR}/get_initial_context.c"
        "${TARGET_SRC_DIR}/init.c"
        "${TARGET_SRC_DIR}/lgetfilecon.c"
        "${TARGET_SRC_DIR}/load_policy.c"
        "${TARGET_SRC_DIR}/lsetfilecon.c"
        "${TARGET_SRC_DIR}/mapping.c"
        "${TARGET_SRC_DIR}/procattr.c"
        "${TARGET_SRC_DIR}/reject_unknown.c"
        "${TARGET_SRC_DIR}/sestatus.c"
        "${TARGET_SRC_DIR}/setenforce.c"
        "${TARGET_SRC_DIR}/setexecfilecon.c"
        "${TARGET_SRC_DIR}/setfilecon.c"
        "${TARGET_SRC_DIR}/stringrep.c"
    )
    list(APPEND TARGET_CFLAGS "-DBUILD_HOST")
elseif (CMAKE_SYSTEM_NAME MATCHES "Android")
    list(APPEND LIBSELINUX_SRCS
        ${LIBSELINUX_DEFAULTS_SRCS}
        "${TARGET_SRC_DIR}/android/android.c"
        "${TARGET_SRC_DIR}/avc.c"
        "${TARGET_SRC_DIR}/avc_internal.c"
        "${TARGET_SRC_DIR}/avc_sidtab.c"
        "${TARGET_SRC_DIR}/canonicalize_context.c"
        "${TARGET_SRC_DIR}/checkAccess.c"
        "${TARGET_SRC_DIR}/check_context.c"
        "${TARGET_SRC_DIR}/compute_av.c"
        "${TARGET_SRC_DIR}/compute_create.c"
        "${TARGET_SRC_DIR}/compute_member.c"
        "${TARGET_SRC_DIR}/context.c"
        "${TARGET_SRC_DIR}/deny_unknown.c"
        "${TARGET_SRC_DIR}/disable.c"
        "${TARGET_SRC_DIR}/enabled.c"
        "${TARGET_SRC_DIR}/fgetfilecon.c"
        "${TARGET_SRC_DIR}/fsetfilecon.c"
        "${TARGET_SRC_DIR}/getenforce.c"
        "${TARGET_SRC_DIR}/getfilecon.c"
        "${TARGET_SRC_DIR}/get_initial_context.c"
        "${TARGET_SRC_DIR}/getpeercon.c"
        "${TARGET_SRC_DIR}/init.c"
        "${TARGET_SRC_DIR}/lgetfilecon.c"
        "${TARGET_SRC_DIR}/load_policy.c"
        "${TARGET_SRC_DIR}/lsetfilecon.c"
        "${TARGET_SRC_DIR}/mapping.c"
        "${TARGET_SRC_DIR}/policyvers.c"
        "${TARGET_SRC_DIR}/procattr.c"
        "${TARGET_SRC_DIR}/reject_unknown.c"
        "${TARGET_SRC_DIR}/sestatus.c"
        "${TARGET_SRC_DIR}/setenforce.c"
        "${TARGET_SRC_DIR}/setfilecon.c"
        "${TARGET_SRC_DIR}/stringrep.c"
        "${TARGET_SRC_DIR}/android/android_platform.c"
    )
    list(APPEND TARGET_CFLAGS "-DAUDITD_LOG_TAG=1003")
endif()

add_library(${TARGET} STATIC ${LIBSELINUX_SRCS})

target_include_directories(${TARGET} PRIVATE
    "${MODULES_SRC}/selinux/libselinux/src"
    "${MODULES_SRC}/selinux/libsepol/include"
    "${MODULES_SRC}/pcre/include"
    "${MODULES_SRC}/core/libpackagelistparser/include"
)

target_compile_options(${TARGET} PRIVATE ${TARGET_CFLAGS})

set(TARGET_LINK_LIBS pcre2)

if (CMAKE_SYSTEM_NAME MATCHES "Android")
    list(APPEND TARGET_LINK_LIBS "packagelistparser")
endif()

target_link_libraries(${TARGET} ${TARGET_LINK_LIBS})
