# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS = foreign
if OS_LINUX
sbin_PROGRAMS    = mount.erofs
AM_CPPFLAGS = ${libuuid_CFLAGS}
mount_erofs_SOURCES = main.c
mount_erofs_CFLAGS = -Wall -I$(top_srcdir)/include
mount_erofs_LDADD = $(top_builddir)/lib/liberofs.la ${libselinux_LIBS} \
	${liblz4_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS} \
	${libzstd_LIBS} ${libqpl_LIBS} ${libxxhash_LIBS} ${libnl3_LIBS}
endif
