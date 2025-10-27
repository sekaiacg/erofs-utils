# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS     = fsck.erofs
AM_CPPFLAGS = ${libuuid_CFLAGS}
fsck_erofs_SOURCES = main.c
fsck_erofs_CFLAGS = -Wall -I$(top_srcdir)/include
fsck_erofs_LDADD = $(top_builddir)/lib/liberofs.la

if ENABLE_FUZZING
noinst_PROGRAMS   = fuzz_erofsfsck
fuzz_erofsfsck_SOURCES = main.c
fuzz_erofsfsck_CFLAGS = -Wall -I$(top_srcdir)/include -DFUZZING
fuzz_erofsfsck_LDFLAGS = -fsanitize=address,fuzzer
fuzz_erofsfsck_LDADD = $(top_builddir)/lib/liberofs.la
endif
