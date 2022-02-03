set(TARGET selinux)

set(SRC_LIST
        ${SRC}/selinux/libselinux/src/canonicalize_context.c
        ${SRC}/selinux/libselinux/src/selinux_config.c
        ${SRC}/selinux/libselinux/src/label_file.c
        ${SRC}/selinux/libselinux/src/regex.c
        ${SRC}/selinux/libselinux/src/callbacks.c
        ${SRC}/selinux/libselinux/src/freecon.c
        ${SRC}/selinux/libselinux/src/label_backends_android.c
        ${SRC}/selinux/libselinux/src/label.c
        ${SRC}/selinux/libselinux/src/label_support.c
        ${SRC}/selinux/libselinux/src/matchpathcon.c
        ${SRC}/selinux/libselinux/src/setrans_client.c
        ${SRC}/selinux/libselinux/src/sha1.c
        ${SRC}/selinux/libselinux/src/init.c
        ${SRC}/selinux/libselinux/src/lgetfilecon.c
        #${SRC}/selinux/libselinux/src/load_policy.c
        ${SRC}/selinux/libselinux/src/lsetfilecon.c
        )

add_library(${TARGET} STATIC ${SRC_LIST})
target_compile_definitions(${TARGET} PRIVATE -DUSE_PCRE2 -DPCRE2_CODE_UNIT_WIDTH=8 -DBUILD_HOST -DNO_DB_BACKEND -DNO_X_BACKEND -DNO_MEDIA_BACKEND -D_GNU_SOURCE -DDISABLE_BOOL -DNO_PERSISTENTLY_STORED_PATTERNS -DDISABLE_SETRANS -DDISABLE_SETRANS)

target_include_directories(${TARGET} PRIVATE ${SRC}/selinux/libselinux/include)

