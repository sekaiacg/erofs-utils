set(TARGET selinux_static)

set(TARGET_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/selinux/libselinux/src")
set(LIBSELINUX_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/libselinux")

set(TARGET_CFLAGS
    "-DNO_PERSISTENTLY_STORED_PATTERNS"
    "-DDISABLE_SETRANS"
    "-DDISABLE_BOOL"
    "-D_GNU_SOURCE"
    "-DNO_MEDIA_BACKEND"
    "-DNO_X_BACKEND"
    "-DNO_DB_BACKEND"
    "-Wall"
    "-Werror"
    "-Wno-error=missing-noreturn"
    "-Wno-error=unused-function"
    "-Wno-error=unused-variable"
    "-Wno-unused-but-set-variable"
    "-DUSE_PCRE2"
    "-DAUDITD_LOG_TAG=1003"
)

if (CMAKE_SYSTEM_NAME STREQUAL "CYGWIN")
    list(APPEND TARGET_CFLAGS "-Wno-char-subscripts")
endif ()

set(libselinux_srcs
    #"android/android.c"
    #"android/android_seapp.c"
    #"avc.c"
    #"avc_internal.c"
    #"avc_sidtab.c"
    #"booleans.c"
    "callbacks.c"
    #"canonicalize_context.c"
    #"checkAccess.c"
    "check_context.c"
    #"compute_av.c"
    #"compute_create.c"
    #"compute_member.c"
    #"context.c"
    #"deny_unknown.c"
    #"disable.c"
    #"enabled.c"
    #"fgetfilecon.c"
    "freecon.c"
    #"fsetfilecon.c"
    #"get_initial_context.c"
    #"getenforce.c"
    #"getfilecon.c"
    #"getpeercon.c"
    "hashtab.c"
    "init.c"
    "label.c"
    "label_backends_android.c"
    "label_file.c"
    "label_support.c"
    #"lgetfilecon.c"
    #"load_policy.c"
    #"lsetfilecon.c"
    #"mapping.c"
    "matchpathcon.c"
    #"policyvers.c"
    #"procattr.c"
    "regex.c"
    #"reject_unknown.c"
    #"selinux_internal.c"
    #"sestatus.c"
    #"setenforce.c"
    #"setfilecon.c"
    "setrans_client.c"
    "sha1.c"
    #"stringrep.c"
)
list(TRANSFORM libselinux_srcs PREPEND "${TARGET_SRC_DIR}/")

if (CMAKE_SYSTEM_NAME MATCHES "CYGWIN")
    list(APPEND TARGET_CFLAGS "-Wno-char-subscripts")
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux|Darwin")
    list(APPEND TARGET_CFLAGS "-DBUILD_HOST")
    if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
        list(APPEND TARGET_CFLAGS "-DHAVE_STRLCPY")
    endif ()
elseif (CMAKE_SYSTEM_NAME MATCHES "Android")
    #	list(APPEND libselinux_srcs "${TARGET_SRC_DIR}/android/android_device.c")
    list(APPEND TARGET_CFLAGS "-DHAVE_STRLCPY")
endif ()

if (CYGWIN)
    list(APPEND TARGET_CFLAGS "-DBUILD_HOST")
endif ()

add_library(${TARGET} STATIC ${libselinux_srcs})

set_target_properties(${TARGET} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${LIBSELINUX_BINARY_DIR})

target_include_directories(${TARGET}
    PRIVATE ${TARGET_SRC_DIR}
    PUBLIC "${TARGET_SRC_DIR}/../include"
)

target_link_libraries(${TARGET} PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,pcre2_static>")

target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
