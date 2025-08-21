#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])

m4_define([erofs_utils_version], m4_esyscmd_s([scripts/get-version-number]))
m4_define([erofs_utils_date], m4_esyscmd([sed -n '2p' VERSION | tr -d '\n']))

AC_INIT([erofs-utils], [erofs_utils_version], [linux-erofs@lists.ozlabs.org])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR(config)

AC_CANONICAL_TARGET

build_linux=no
case "${target_os}" in
  linux*)
    build_linux=yes
    ;;
esac

# OS-specific treatment
AM_CONDITIONAL([OS_LINUX], [test "$build_linux" = "yes"])

AM_INIT_AUTOMAKE([foreign subdir-objects -Wall])

# Checks for programs.
AM_PROG_AR
AC_PROG_CC
AC_PROG_INSTALL

LT_INIT

# Test presence of pkg-config
AC_MSG_CHECKING([pkg-config m4 macros])
if test m4_ifdef([PKG_CHECK_MODULES], [yes], [no]) = "yes"; then
  AC_MSG_RESULT([yes]);
else
  AC_MSG_RESULT([no]);
  AC_MSG_ERROR([pkg-config is required. See pkg-config.freedesktop.org])
fi

dnl Check if the flag is supported by compiler
dnl CC_CHECK_CFLAGS_SILENT([FLAG], [ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND])
AC_DEFUN([CC_CHECK_CFLAGS_SILENT], [
  AC_CACHE_VAL(AS_TR_SH([cc_cv_cflags_$1]),
    [ac_save_CFLAGS="$CFLAGS"
     CFLAGS="$CFLAGS $1"
     AC_LINK_IFELSE([AC_LANG_SOURCE([int main() { return 0; }])],
       [eval "AS_TR_SH([cc_cv_cflags_$1])='yes'"],
       [eval "AS_TR_SH([cc_cv_cflags_$1])='no'"])
     CFLAGS="$ac_save_CFLAGS"
    ])

  AS_IF([eval test x$]AS_TR_SH([cc_cv_cflags_$1])[ = xyes],
    [$2], [$3])
])

dnl Check if the flag is supported by compiler (cacheable)
dnl CC_CHECK_CFLAG([FLAG], [ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND])
AC_DEFUN([CC_CHECK_CFLAG], [
  AC_CACHE_CHECK([if $CC supports $1 flag],
    AS_TR_SH([cc_cv_cflags_$1]),
    CC_CHECK_CFLAGS_SILENT([$1]) dnl Don't execute actions here!
  )

  AS_IF([eval test x$]AS_TR_SH([cc_cv_cflags_$1])[ = xyes],
    [$2], [$3])
])

dnl CC_CHECK_CFLAGS([FLAG1 FLAG2], [action-if-found], [action-if-not])
AC_DEFUN([CC_CHECK_CFLAGS], [
  for flag in $1; do
    CC_CHECK_CFLAG($flag, [$2], [$3])
  done
])

dnl EROFS_UTILS_PARSE_DIRECTORY
dnl Input:  $1 = a string to a relative or absolute directory
dnl Output: $2 = the variable to set with the absolute directory
AC_DEFUN([EROFS_UTILS_PARSE_DIRECTORY],
[
 dnl Check if argument is a directory
 if test -d $1 ; then
    dnl Get the absolute path of the directory
    dnl in case of relative directory.
    dnl If realpath is not a valid command,
    dnl an error is produced and we keep the given path.
    local_tmp=`realpath $1 2>/dev/null`
    if test "$local_tmp" != "" ; then
       if test -d "$local_tmp" ; then
           $2="$local_tmp"
       else
           $2=$1
       fi
    else
       $2=$1
    fi
    dnl Check for space in the directory
    if test `echo $1|cut -d' ' -f1` != $1 ; then
        AC_MSG_ERROR($1 directory shall not contain any space.)
    fi
 else
    AC_MSG_ERROR($1 shall be a valid directory)
 fi
])

AC_ARG_VAR([MAX_BLOCK_SIZE], [The maximum block size which erofs-utils supports])

AC_MSG_CHECKING([whether to enable multi-threading support])
AC_ARG_ENABLE([multithreading],
    AS_HELP_STRING([--disable-multithreading],
                   [disable multi-threading support @<:@default=yes@:>@]),
    [enable_multithreading="$enableval"],
    [enable_multithreading="yes"])
AC_MSG_RESULT([$enable_multithreading])

AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
                    [enable debugging mode @<:@default=no@:>@])],
    [enable_debug="$enableval"],
    [enable_debug="no"])

AC_ARG_ENABLE([werror],
    [AS_HELP_STRING([--enable-werror],
                    [enable -Werror @<:@default=no@:>@])],
    [enable_werror="$enableval"],
    [enable_werror="no"])

AC_ARG_ENABLE([fuzzing],
    [AS_HELP_STRING([--enable-fuzzing],
                    [set up fuzzing mode @<:@default=no@:>@])],
    [enable_fuzzing="$enableval"],
    [enable_fuzzing="no"])

AC_ARG_ENABLE(lz4,
   [AS_HELP_STRING([--disable-lz4], [disable LZ4 compression support @<:@default=auto@:>@])],
   [enable_lz4="$enableval"])

AC_ARG_ENABLE(lzma,
   [AS_HELP_STRING([--disable-lzma], [disable LZMA compression support @<:@default=auto@:>@])],
   [enable_lzma="$enableval"])

AC_ARG_WITH(zlib,
   [AS_HELP_STRING([--without-zlib],
      [Ignore presence of zlib inflate support @<:@default=auto@:>@])])

AC_ARG_WITH(libdeflate,
   [AS_HELP_STRING([--with-libdeflate],
      [Enable and build with libdeflate inflate support @<:@default=disabled@:>@])], [],
      [with_libdeflate="no"])

AC_ARG_WITH(libzstd,
   [AS_HELP_STRING([--with-libzstd],
      [Enable and build with of libzstd support @<:@default=auto@:>@])])

AC_ARG_WITH(qpl,
   [AS_HELP_STRING([--with-qpl],
      [Enable and build with Intel QPL support @<:@default=disabled@:>@])], [],
      [with_qpl="no"])

AC_ARG_WITH(xxhash,
   [AS_HELP_STRING([--with-xxhash],
      [Enable and build with libxxhash support @<:@default=auto@:>@])])

AC_ARG_WITH(libcurl,
   [AS_HELP_STRING([--with-libcurl],
      [Enable and build with libcurl support @<:@default=auto@:>@])])

AC_ARG_WITH(openssl,
   [AS_HELP_STRING([--with-openssl],
      [Enable and build with openssl support @<:@default=auto@:>@])])

AC_ARG_WITH(libxml2,
   [AS_HELP_STRING([--with-libxml2],
      [Enable and build with libxml2 support @<:@default=auto@:>@])])

AC_ARG_ENABLE(s3,
   [AS_HELP_STRING([--enable-s3], [enable s3 image generation support @<:@default=no@:>@])],
   [enable_s3="$enableval"], [enable_s3="no"])

AC_ARG_ENABLE(fuse,
   [AS_HELP_STRING([--enable-fuse], [enable erofsfuse @<:@default=no@:>@])],
   [enable_fuse="$enableval"], [enable_fuse="no"])

AC_ARG_ENABLE([static-fuse],
    [AS_HELP_STRING([--enable-static-fuse],
                    [build erofsfuse as a static library @<:@default=no@:>@])],
    [enable_static_fuse="$enableval"],
    [enable_static_fuse="no"])

AC_ARG_WITH(uuid,
   [AS_HELP_STRING([--without-uuid],
      [Ignore presence of libuuid and disable uuid support @<:@default=enabled@:>@])])

AC_ARG_WITH(selinux,
   [AS_HELP_STRING([--with-selinux],
      [enable and build with selinux support @<:@default=no@:>@])],
   [case "$with_selinux" in
      yes|no) ;;
      *) AC_MSG_ERROR([invalid argument to --with-selinux])
      ;;
    esac], [with_selinux=no])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS(m4_flatten([
	dirent.h
	execinfo.h
	endian.h
	fcntl.h
	getopt.h
	inttypes.h
	linux/aufs_type.h
	linux/falloc.h
	linux/fs.h
	linux/loop.h
	linux/types.h
	linux/xattr.h
	limits.h
	stddef.h
	stdint.h
	stdlib.h
	string.h
	sys/ioctl.h
	sys/mman.h
	sys/random.h
	sys/resource.h
	sys/sendfile.h
	sys/stat.h
	sys/statfs.h
	sys/sysmacros.h
	sys/time.h
	sys/uio.h
	unistd.h
]))

AC_HEADER_TIOCGWINSZ

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_CHECK_MEMBERS([struct stat.st_atim])
AC_CHECK_MEMBERS([struct stat.st_atimensec])
AC_TYPE_UINT64_T

#
# Check to see if llseek() is declared in unistd.h.  On some libc's
# it is, and on others it isn't..... Thank you glibc developers....
#
AC_CHECK_DECL(llseek,
  [AC_DEFINE(HAVE_LLSEEK_PROTOTYPE, 1,
    [Define to 1 if llseek declared in unistd.h])],,
  [#include <unistd.h>])

#
# Check to see if lseek64() is declared in unistd.h.  Glibc's header files
# are so convoluted that I can't tell whether it will always be defined,
# and if it isn't defined while lseek64 is defined in the library,
# disaster will strike.
#
# Warning!  Use of --enable-gcc-wall may throw off this test.
#
AC_CHECK_DECL(lseek64,[AC_DEFINE(HAVE_LSEEK64_PROTOTYPE, 1,
  [Define to 1 if lseek64 declared in unistd.h])],,
  [#define _LARGEFILE_SOURCE
   #define _LARGEFILE64_SOURCE
   #include <unistd.h>])

AC_CHECK_DECL(memrchr,[AC_DEFINE(HAVE_MEMRCHR, 1,
  [Define to 1 if memrchr declared in string.h])],,
  [#define _GNU_SOURCE
   #include <string.h>])

# Checks for library functions.
AC_CHECK_FUNCS(m4_flatten([
	backtrace
	copy_file_range
	fallocate
	getrandom
	getrlimit
	gettimeofday
	lgetxattr
	llistxattr
	lsetxattr
	memset
	realpath
	lseek64
	ftello64
	pread64
	pwrite64
	pwritev
	posix_fadvise
	fstatfs
	sendfile
	strdup
	strerror
	strrchr
	strtoull
	sysconf
	utimensat]))

# Detect maximum block size if necessary
AS_IF([test "x$MAX_BLOCK_SIZE" = "x"], [
  AC_CACHE_CHECK([sysconf (_SC_PAGESIZE)], [erofs_cv_max_block_size],
               AC_RUN_IFELSE([AC_LANG_PROGRAM(
[[
#include <unistd.h>
#include <stdio.h>
]],
[[
    int result;
    FILE *f;

    result = sysconf(_SC_PAGESIZE);
    if (result < 0)
	return 1;

    f = fopen("conftest.out", "w");
    if (!f)
	return 1;

    fprintf(f, "%d", result);
    fclose(f);
    return 0;
]])],
                             [erofs_cv_max_block_size=`cat conftest.out`],
                             [erofs_cv_max_block_size=4096],
                             [erofs_cv_max_block_size=4096]))
], [erofs_cv_max_block_size=$MAX_BLOCK_SIZE])

# Configure multi-threading support
AS_IF([test "x$enable_multithreading" != "xno"], [
  AC_CHECK_HEADERS([pthread.h])
  AC_CHECK_LIB([pthread], [pthread_mutex_lock], [],
    AC_MSG_ERROR([libpthread is required for multi-threaded build]))
  AC_DEFINE(EROFS_MT_ENABLED, 1, [Enable multi-threading support])
], [])

# Configure debug mode
AS_IF([test "x$enable_debug" != "xno"], [], [
  dnl Turn off all assert checking.
  CPPFLAGS="$CPPFLAGS -DNDEBUG"
])

# Configure -Werror
AS_IF([test "x$enable_werror" != "xyes"], [], [
  CPPFLAGS="$CPPFLAGS -Werror"
])

# Configure libuuid
AS_IF([test "x$with_uuid" != "xno"], [
  PKG_CHECK_MODULES([libuuid], [uuid])
  # Paranoia: don't trust the result reported by pkgconfig before trying out
  saved_LIBS="$LIBS"
  saved_CPPFLAGS=${CPPFLAGS}
  CPPFLAGS="${libuuid_CFLAGS} ${CPPFLAGS}"
  LIBS="${libuuid_LIBS} $LIBS"
  AC_MSG_CHECKING([libuuid usability])
  AC_TRY_LINK([
#include <uuid.h>
], [
uuid_t tmp;

uuid_generate(tmp);
return 0;
], [have_uuid="yes"
    AC_MSG_RESULT([yes])], [
    have_uuid="no"
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([libuuid doesn't work properly])])
  LIBS="${saved_LIBS}"
  CPPFLAGS="${saved_CPPFLAGS}"], [have_uuid="no"])

# Configure selinux
AS_IF([test "x$with_selinux" != "xno"], [
  PKG_CHECK_MODULES([libselinux], [libselinux])
  # Paranoia: don't trust the result reported by pkgconfig before trying out
  saved_LIBS="$LIBS"
  saved_CPPFLAGS=${CPPFLAGS}
  CPPFLAGS="${libselinux_CFLAGS} ${CPPFLAGS}"
  LIBS="${libselinux_LIBS} $LIBS"
  AC_CHECK_LIB(selinux, selabel_lookup, [
    have_selinux="yes" ], [
    AC_MSG_ERROR([libselinux doesn't work properly])])
  LIBS="${saved_LIBS}"
  CPPFLAGS="${saved_CPPFLAGS}"], [have_selinux="no"])

# Configure fuse
AS_IF([test "x$enable_fuse" != "xno"], [
  # Paranoia: don't trust the result reported by pkgconfig before trying out
  saved_LIBS="$LIBS"
  saved_CPPFLAGS=${CPPFLAGS}
  PKG_CHECK_MODULES([libfuse3], [fuse3 >= 3.0], [
    PKG_CHECK_MODULES([libfuse3_0], [fuse3 >= 3.0 fuse3 < 3.2], [
      AC_DEFINE([FUSE_USE_VERSION], [30], [used FUSE API version])
    ], [
      PKG_CHECK_MODULES([libfuse3_2], [fuse3 >= 3.2], [
        AC_DEFINE([FUSE_USE_VERSION], [32], [used FUSE API version])
      ])
    ])
    CPPFLAGS="${libfuse3_CFLAGS} ${CPPFLAGS}"
    LIBS="${libfuse3_LIBS} $LIBS"
    AC_CHECK_LIB(fuse3, fuse_session_new, [], [
    AC_MSG_ERROR([libfuse3 (>= 3.0) doesn't work properly for lowlevel api])])
    have_fuse="yes"
  ], [
    PKG_CHECK_MODULES([libfuse2], [fuse >= 2.6], [
      AC_DEFINE([FUSE_USE_VERSION], [26], [used FUSE API version])
      CPPFLAGS="${libfuse2_CFLAGS} ${CPPFLAGS}"
      LIBS="${libfuse2_LIBS} $LIBS"
      AC_CHECK_LIB(fuse, fuse_lowlevel_new, [], [
        AC_MSG_ERROR([libfuse (>= 2.6) doesn't work properly for lowlevel api])])
      have_fuse="yes"
    ], [have_fuse="no"])
  ])
  AC_CHECK_MEMBERS([struct fuse_file_info.cache_readdir, struct fuse_file_info.keep_cache],
    [], [], [[
#include <fuse.h>
  ]])

  LIBS="${saved_LIBS}"
  CPPFLAGS="${saved_CPPFLAGS}"], [have_fuse="no"])

# Configure lz4
AS_IF([test "x$enable_lz4" != "xno"], [
  saved_CPPFLAGS=${CPPFLAGS}
  PKG_CHECK_MODULES([liblz4], [liblz4], [
    # Paranoia: don't trust the result reported by pkgconfig before trying out
    saved_LIBS="$LIBS"
    saved_CPPFLAGS=${CPPFLAGS}
    CPPFLAGS="${liblz4_CFLAGS} ${CPPFLAGS}"
    LIBS="${liblz4_LIBS} $LIBS"
    AC_CHECK_HEADERS([lz4.h],[
      AC_CHECK_LIB(lz4, LZ4_compress_destSize, [
        AC_CHECK_DECL(LZ4_compress_destSize, [have_lz4="yes"],
          [], [[
#include <lz4.h>
        ]])
      ])
      AC_CHECK_LIB(lz4, LZ4_compress_HC_destSize, [
        AC_CHECK_DECL(LZ4_compress_HC_destSize, [have_lz4hc="yes"],
          [], [[
#include <lz4hc.h>
        ]])
      ])
    ])
    LIBS="${saved_LIBS}"
    CPPFLAGS="${saved_CPPFLAGS}"
  ], [[]])
  AS_IF([test "x$enable_lz4" = "xyes" -a "x$have_lz4" != "xyes"], [
    AC_MSG_ERROR([Cannot find a proper liblz4 version])
  ])
])

# Configure liblzma
have_liblzma="no"
AS_IF([test "x$enable_lzma" != "xno"], [
  saved_CPPFLAGS=${CPPFLAGS}
  PKG_CHECK_MODULES([liblzma], [liblzma], [
    # Paranoia: don't trust the result reported by pkgconfig before trying out
    saved_LIBS="$LIBS"
    saved_CPPFLAGS=${CPPFLAGS}
    CPPFLAGS="${liblzma_CFLAGS} ${CPPFLAGS}"
    LIBS="${liblzma_LIBS} $LIBS"
    AC_CHECK_HEADERS([lzma.h],[
      AC_CHECK_LIB(lzma, lzma_microlzma_encoder, [
        AC_CHECK_DECL(lzma_microlzma_encoder, [have_liblzma="yes"],
          [], [[
#include <lzma.h>
        ]])
      ])
    ])
    LIBS="${saved_LIBS}"
    CPPFLAGS="${saved_CPPFLAGS}"
  ], [[]])
  AS_IF([test "x$enable_lzma" = "xyes" -a "x$have_liblzma" != "xyes"], [
    AC_MSG_ERROR([Cannot find a proper liblzma version])
  ])
])

# Configure zlib
have_zlib="no"
AS_IF([test "x$with_zlib" != "xno"], [
  PKG_CHECK_MODULES([zlib], [zlib], [
    # Paranoia: don't trust the result reported by pkgconfig before trying out
    saved_LIBS="$LIBS"
    saved_CPPFLAGS=${CPPFLAGS}
    CPPFLAGS="${zlib_CFLAGS} ${CPPFLAGS}"
    LIBS="${zlib_LIBS} $LIBS"
    AC_CHECK_HEADERS([zlib.h],[
      AC_CHECK_LIB(z, inflate, [], [
        AC_MSG_ERROR([zlib doesn't work properly])])
      AC_CHECK_DECL(inflate, [have_zlib="yes"],
        [AC_MSG_ERROR([zlib doesn't work properly])], [[
#include <zlib.h>
      ]])
    ])
    LIBS="${saved_LIBS}"
    CPPFLAGS="${saved_CPPFLAGS}"], [
    AS_IF([test "x$with_zlib" = "xyes"], [
      AC_MSG_ERROR([Cannot find proper zlib])
    ])
  ])
])

# Configure libdeflate
AS_IF([test "x$with_libdeflate" != "xno"], [
  PKG_CHECK_MODULES([libdeflate], [libdeflate])
  # Paranoia: don't trust the result reported by pkgconfig before trying out
  saved_LIBS="$LIBS"
  saved_CPPFLAGS=${CPPFLAGS}
  CPPFLAGS="${libdeflate_CFLAGS} ${CPPFLAGS}"
  LIBS="${libdeflate_LIBS} $LIBS"
  AC_CHECK_LIB(deflate, libdeflate_deflate_decompress, [
    have_libdeflate="yes" ], [
    AC_MSG_ERROR([libdeflate doesn't work properly])])
  LIBS="${saved_LIBS}"
  CPPFLAGS="${saved_CPPFLAGS}"], [have_libdeflate="no"])

# Configure libzstd
have_libzstd="no"
AS_IF([test "x$with_libzstd" != "xno"], [
  PKG_CHECK_MODULES([libzstd], [libzstd >= 1.4.0], [
    # Paranoia: don't trust the result reported by pkgconfig before trying out
    saved_LIBS="$LIBS"
    saved_CPPFLAGS=${CPPFLAGS}
    CPPFLAGS="${libzstd_CFLAGS} ${CPPFLAGS}"
    LIBS="${libzstd_LIBS} $LIBS"
    AC_CHECK_HEADERS([zstd.h],[
      AC_CHECK_LIB(zstd, ZSTD_compress2, [], [
        AC_MSG_ERROR([libzstd doesn't work properly])])
      AC_CHECK_DECL(ZSTD_compress2, [have_libzstd="yes"],
        [AC_MSG_ERROR([libzstd doesn't work properly])], [[
#include <zstd.h>
      ]])
      AC_CHECK_FUNCS([ZSTD_getFrameContentSize])
    ])
    LIBS="${saved_LIBS}"
    CPPFLAGS="${saved_CPPFLAGS}"], [
    AS_IF([test "x$with_libzstd" = "xyes"], [
      AC_MSG_ERROR([Cannot find proper libzstd])
    ])
  ])
])

# Configure Intel QPL
have_qpl="no"
AS_IF([test "x$with_qpl" != "xno"], [
  PKG_CHECK_MODULES([libqpl], [qpl >= 1.5.0], [
    # Paranoia: don't trust the result reported by pkgconfig before trying out
    saved_LIBS="$LIBS"
    saved_CPPFLAGS=${CPPFLAGS}
    CPPFLAGS="${libqpl_CFLAGS} ${CPPFLAGS}"
    LIBS="${libqpl_LIBS} $LIBS"
    AC_CHECK_HEADERS([qpl/qpl.h],[
      AC_CHECK_LIB(qpl, qpl_execute_job, [], [
        AC_MSG_ERROR([libqpl doesn't work properly])])
      AC_CHECK_DECL(qpl_execute_job, [have_qpl="yes"],
        [AC_MSG_ERROR([libqpl doesn't work properly])], [[
#include <qpl/qpl.h>
      ]])
    ])
    LIBS="${saved_LIBS}"
    CPPFLAGS="${saved_CPPFLAGS}"], [
    AS_IF([test "x$with_qpl" = "xyes"], [
      AC_MSG_ERROR([Cannot find proper libqpl])
    ])
  ])
])

# Configure libxxhash
have_xxhash="no"
AS_IF([test "x$with_xxhash" != "xno"], [
  PKG_CHECK_MODULES([libxxhash], [libxxhash], [
    # Paranoia: don't trust the result reported by pkgconfig before trying out
    saved_LIBS="$LIBS"
    saved_CPPFLAGS=${CPPFLAGS}
    CPPFLAGS="${libxxhash_CFLAGS} ${CPPFLAGS}"
    LIBS="${libxxhash_LIBS} $LIBS"
    AC_CHECK_HEADERS([xxhash.h],[
      AC_CHECK_LIB(xxhash, XXH32, [], [
        AC_MSG_ERROR([libxxhash doesn't work properly])])
      AC_CHECK_DECL(XXH32, [have_xxhash="yes"],
        [AC_MSG_ERROR([libxxhash doesn't work properly])], [[
#include <xxhash.h>
      ]])
    ])
    LIBS="${saved_LIBS}"
    CPPFLAGS="${saved_CPPFLAGS}"], [
    AS_IF([test "x$with_xxhash" = "xyes"], [
      AC_MSG_ERROR([Cannot find proper libxxhash])
    ])
  ])
])

# Configure libcurl
have_libcurl="no"
AS_IF([test "x$with_libcurl" != "xno"], [
  PKG_CHECK_MODULES([libcurl], [libcurl], [
    # Paranoia: don't trust the result reported by pkgconfig before trying out
    saved_LIBS="$LIBS"
    saved_CPPFLAGS=${CPPFLAGS}
    CPPFLAGS="${libcurl_CFLAGS} ${CPPFLAGS}"
    LIBS="${libcurl_LIBS} $LIBS"
    AC_CHECK_HEADERS([curl/curl.h],[
      AC_CHECK_LIB(curl, curl_easy_perform, [], [
        AC_MSG_ERROR([libcurl doesn't work properly])])
      AC_CHECK_DECL(curl_easy_perform, [have_libcurl="yes"],
        [AC_MSG_ERROR([libcurl doesn't work properly])], [[
#include <curl/curl.h>
      ]])
    ])
    LIBS="${saved_LIBS}"
    CPPFLAGS="${saved_CPPFLAGS}"], [
    AS_IF([test "x$with_libcurl" = "xyes"], [
      AC_MSG_ERROR([Cannot find proper libcurl])
    ])
  ])
])

# Configure openssl
have_openssl="no"
AS_IF([test "x$with_openssl" != "xno"], [
  PKG_CHECK_MODULES([openssl], [openssl], [
    # Paranoia: don't trust the result reported by pkgconfig before trying out
    saved_LIBS="$LIBS"
    saved_CPPFLAGS=${CPPFLAGS}
    CPPFLAGS="${openssl_CFLAGS} ${CPPFLAGS}"
    LIBS="${openssl_LIBS} $LIBS"
    AC_CHECK_HEADERS([openssl/hmac.h],[
      AC_CHECK_LIB(ssl, EVP_sha1, [], [
        AC_MSG_ERROR([openssl doesn't work properly])])
      AC_CHECK_DECL(EVP_sha1, [have_openssl="yes"],
        [AC_MSG_ERROR([openssl doesn't work properly])], [[
#include <openssl/hmac.h>
      ]])
    ])
    AC_CHECK_HEADERS([openssl/evp.h],[],[])
    LIBS="${saved_LIBS}"
    CPPFLAGS="${saved_CPPFLAGS}"], [
    AS_IF([test "x$with_openssl" = "xyes"], [
      AC_MSG_ERROR([Cannot find proper openssl])
    ])
  ])
])

# Configure libxml2
have_libxml2="no"
AS_IF([test "x$with_libxml2" != "xno"], [
  PKG_CHECK_MODULES([libxml2], [libxml-2.0], [
    # Paranoia: don't trust the result reported by pkgconfig before trying out
    saved_LIBS="$LIBS"
    saved_CPPFLAGS=${CPPFLAGS}
    CPPFLAGS="${libxml2_CFLAGS} ${CPPFLAGS}"
    LIBS="${libxml2_LIBS} $LIBS"
    AC_CHECK_HEADERS([libxml/parser.h],[
      AC_CHECK_LIB(xml2, xmlReadMemory, [], [
        AC_MSG_ERROR([libxml2 doesn't work properly])])
      AC_CHECK_DECL(xmlReadMemory, [have_libxml2="yes"],
        [AC_MSG_ERROR([libxml2 doesn't work properly])], [[
#include <libxml/parser.h>
      ]])
    ])
    LIBS="${saved_LIBS}"
    CPPFLAGS="${saved_CPPFLAGS}"], [
    AS_IF([test "x$with_libxml2" = "xyes"], [
      AC_MSG_ERROR([Cannot find proper libxml2])
    ])
  ])
])

AS_IF([test "x$enable_s3" != "xno"], [
  AS_IF(
    [test "x$have_libcurl" = "xyes" && \
     test "x$have_openssl" = "xyes" && \
     test "x$have_libxml2" = "xyes"],
    [have_s3="yes"],
    [have_s3="no"
     AC_MSG_ERROR([S3 disabled: missing libcurl, openssl, or libxml2])])
  ], [have_s3="no"])

# Enable 64-bit off_t
CFLAGS+=" -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"

# Configure fuzzing mode
AS_IF([test "x$enable_fuzzing" != "xyes"], [], [
  CC_CHECK_CFLAGS(["-fsanitize=address,fuzzer-no-link"], [
    CFLAGS="$CFLAGS -g -O1 -fsanitize=address,fuzzer-no-link"
  ], [
    AC_MSG_ERROR([Compiler doesn't support `-fsanitize=address,fuzzer-no-link`])
  ])
])
AM_CONDITIONAL([ENABLE_FUZZING], [test "x${enable_fuzzing}" = "xyes"])

# Set up needed symbols, conditionals and compiler/linker flags
AM_CONDITIONAL([ENABLE_EROFS_MT], [test "x${enable_multithreading}" != "xno"])
AM_CONDITIONAL([ENABLE_LZ4], [test "x${have_lz4}" = "xyes"])
AM_CONDITIONAL([ENABLE_LZ4HC], [test "x${have_lz4hc}" = "xyes"])
AM_CONDITIONAL([ENABLE_FUSE], [test "x${have_fuse}" = "xyes"])
AM_CONDITIONAL([ENABLE_LIBLZMA], [test "x${have_liblzma}" = "xyes"])
AM_CONDITIONAL([ENABLE_LIBDEFLATE], [test "x${have_libdeflate}" = "xyes"])
AM_CONDITIONAL([ENABLE_LIBZSTD], [test "x${have_libzstd}" = "xyes"])
AM_CONDITIONAL([ENABLE_QPL], [test "x${have_qpl}" = "xyes"])
AM_CONDITIONAL([ENABLE_XXHASH], [test "x${have_xxhash}" = "xyes"])
AM_CONDITIONAL([ENABLE_LIBCURL], [test "x${have_libcurl}" = "xyes"])
AM_CONDITIONAL([ENABLE_OPENSSL], [test "x${have_openssl}" = "xyes"])
AM_CONDITIONAL([ENABLE_LIBXML2], [test "x${have_libxml2}" = "xyes"])
AM_CONDITIONAL([ENABLE_S3], [test "x${have_s3}" = "xyes"])
AM_CONDITIONAL([ENABLE_STATIC_FUSE], [test "x${enable_static_fuse}" = "xyes"])

if test "x$have_uuid" = "xyes"; then
  AC_DEFINE([HAVE_LIBUUID], 1, [Define to 1 if libuuid is found])
fi

if test "x$have_selinux" = "xyes"; then
  AC_DEFINE([HAVE_LIBSELINUX], 1, [Define to 1 if libselinux is found])
fi

if test "x${have_lz4}" = "xyes"; then
  AC_DEFINE([LZ4_ENABLED], [1], [Define to 1 if lz4 is enabled.])

  if test "x${have_lz4hc}" = "xyes"; then
    AC_DEFINE([LZ4HC_ENABLED], [1], [Define to 1 if lz4hc is enabled.])
  fi
fi

if test "x${have_liblzma}" = "xyes"; then
  AC_DEFINE([HAVE_LIBLZMA], [1], [Define to 1 if liblzma is enabled.])
  liblzma_LIBS="-llzma"
  test -z "${with_liblzma_libdir}" ||
    liblzma_LIBS="-L${with_liblzma_libdir} $liblzma_LIBS"
  test -z "${with_liblzma_incdir}" ||
    liblzma_CFLAGS="-I${with_liblzma_incdir}"
  AC_SUBST([liblzma_LIBS])
  AC_SUBST([liblzma_CFLAGS])
fi

if test "x$have_zlib" = "xyes"; then
  AC_DEFINE([HAVE_ZLIB], 1, [Define to 1 if zlib is found])
fi

if test "x$have_libdeflate" = "xyes"; then
  AC_DEFINE([HAVE_LIBDEFLATE], 1, [Define to 1 if libdeflate is found])
fi

if test "x$have_libzstd" = "xyes"; then
  AC_DEFINE([HAVE_LIBZSTD], 1, [Define to 1 if libzstd is found])
fi

if test "x$have_qpl" = "xyes"; then
  AC_DEFINE([HAVE_QPL], 1, [Define to 1 if qpl is found])
  AC_SUBST([libqpl_LIBS])
  AC_SUBST([libqpl_CFLAGS])
fi

if test "x$have_xxhash" = "xyes"; then
  AC_DEFINE([HAVE_XXHASH], 1, [Define to 1 if xxhash is found])
fi

if test "x$have_libcurl" = "xyes"; then
  AC_DEFINE([HAVE_LIBCURL], 1, [Define to 1 if libcurl is found])
  AC_SUBST([libcurl_LIBS])
  AC_SUBST([libcurl_CFLAGS])
fi

if test "x$have_openssl" = "xyes"; then
  AC_DEFINE([HAVE_OPENSSL], 1, [Define to 1 if openssl is found])
  AC_SUBST([openssl_LIBS])
  AC_SUBST([openssl_CFLAGS])
fi

if test "x$have_libxml2" = "xyes"; then
  AC_DEFINE([HAVE_LIBXML2], 1, [Define to 1 if libxml2 is found])
  AC_SUBST([libxml2_LIBS])
  AC_SUBST([libxml2_CFLAGS])
fi

if test "x$have_s3" = "xyes"; then
  AC_DEFINE([S3EROFS_ENABLED], 1, [Define to 1 if s3 is enabled])
fi

# Dump maximum block size
AS_IF([test "x$erofs_cv_max_block_size" = "x"],
      [$erofs_cv_max_block_size = 4096], [])

AC_DEFINE_UNQUOTED([EROFS_MAX_BLOCK_SIZE], [$erofs_cv_max_block_size],
		   [The maximum block size which erofs-utils supports])

AC_CONFIG_FILES([Makefile
		 man/Makefile
		 lib/Makefile
		 mkfs/Makefile
		 dump/Makefile
		 fuse/Makefile
		 fsck/Makefile
		 mount/Makefile
		 contrib/Makefile])
AC_OUTPUT
