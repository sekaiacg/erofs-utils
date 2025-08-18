# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS     = dump.erofs
AM_CPPFLAGS = ${libuuid_CFLAGS}
dump_erofs_SOURCES = main.c
dump_erofs_CFLAGS = -Wall -I$(top_srcdir)/include
dump_erofs_LDADD = $(top_builddir)/lib/liberofs.la ${libselinux_LIBS} \
	${liblz4_LIBS} ${liblzma_LIBS} ${zlib_LIBS} ${libdeflate_LIBS} \
	${libzstd_LIBS} ${libqpl_LIBS} ${libxxhash_LIBS} ${openssl_LIBS}
