# SPDX-License-Identifier: GPL-2.0+

AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS     = mkfs.erofs
AM_CPPFLAGS = ${libselinux_CFLAGS}
mkfs_erofs_SOURCES = main.c
mkfs_erofs_CFLAGS = -Wall -I$(top_srcdir)/include
mkfs_erofs_LDADD = $(top_builddir)/lib/liberofs.la
