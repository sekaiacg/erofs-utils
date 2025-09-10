# SPDX-License-Identifier: GPL-2.0+ OR Apache-2.0

noinst_LTLIBRARIES = liberofs.la
noinst_HEADERS = $(top_srcdir)/include/erofs_fs.h \
      $(top_srcdir)/include/erofs/blobchunk.h \
      $(top_srcdir)/include/erofs/block_list.h \
      $(top_srcdir)/include/erofs/compress.h \
      $(top_srcdir)/include/erofs/config.h \
      $(top_srcdir)/include/erofs/decompress.h \
      $(top_srcdir)/include/erofs/defs.h \
      $(top_srcdir)/include/erofs/diskbuf.h \
      $(top_srcdir)/include/erofs/err.h \
      $(top_srcdir)/include/erofs/exclude.h \
      $(top_srcdir)/include/erofs/flex-array.h \
      $(top_srcdir)/include/erofs/hashmap.h \
      $(top_srcdir)/include/erofs/hashtable.h \
      $(top_srcdir)/include/erofs/inode.h \
      $(top_srcdir)/include/erofs/internal.h \
      $(top_srcdir)/include/erofs/io.h \
      $(top_srcdir)/include/erofs/list.h \
      $(top_srcdir)/include/erofs/print.h \
      $(top_srcdir)/include/erofs/bitops.h \
      $(top_srcdir)/include/erofs/tar.h \
      $(top_srcdir)/include/erofs/trace.h \
      $(top_srcdir)/include/erofs/xattr.h \
      $(top_srcdir)/include/erofs/compress_hints.h \
      $(top_srcdir)/include/erofs/fragments.h \
      $(top_srcdir)/include/erofs/rebuild.h \
      $(top_srcdir)/include/erofs/importer.h \
      $(top_srcdir)/lib/liberofs_base64.h \
      $(top_srcdir)/lib/liberofs_cache.h \
      $(top_srcdir)/lib/liberofs_private.h \
      $(top_srcdir)/lib/liberofs_xxhash.h \
      $(top_srcdir)/lib/liberofs_metabox.h \
      $(top_srcdir)/lib/liberofs_nbd.h \
      $(top_srcdir)/lib/liberofs_s3.h

noinst_HEADERS += compressor.h
liberofs_la_SOURCES = config.c io.c cache.c super.c inode.c xattr.c exclude.c \
		      namei.c data.c compress.c compressor.c zmap.c decompress.c \
		      compress_hints.c hashmap.c sha256.c blobchunk.c dir.c \
		      fragments.c dedupe.c uuid_unparse.c uuid.c tar.c \
		      block_list.c rebuild.c diskbuf.c bitops.c dedupe_ext.c \
		      vmdk.c metabox.c global.c importer.c base64.c

liberofs_la_CFLAGS = -Wall ${libuuid_CFLAGS} -I$(top_srcdir)/include
liberofs_la_LDFLAGS =
if ENABLE_LZ4
liberofs_la_CFLAGS += ${liblz4_CFLAGS}
liberofs_la_SOURCES += compressor_lz4.c
if ENABLE_LZ4HC
liberofs_la_SOURCES += compressor_lz4hc.c
endif
endif
if ENABLE_LIBLZMA
liberofs_la_CFLAGS += ${liblzma_CFLAGS}
liberofs_la_SOURCES += compressor_liblzma.c
endif

liberofs_la_SOURCES += kite_deflate.c compressor_deflate.c
if ENABLE_LIBDEFLATE
liberofs_la_CFLAGS += ${libdeflate_CFLAGS}
liberofs_la_SOURCES += compressor_libdeflate.c
endif
if ENABLE_LIBZSTD
liberofs_la_CFLAGS += ${libzstd_CFLAGS}
liberofs_la_SOURCES += compressor_libzstd.c
endif
if ENABLE_XXHASH
liberofs_la_CFLAGS += ${libxxhash_CFLAGS}
else
liberofs_la_SOURCES += xxhash.c
endif
liberofs_la_CFLAGS += ${libcurl_CFLAGS} ${openssl_CFLAGS} ${libxml2_CFLAGS}
if ENABLE_S3
liberofs_la_SOURCES += remotes/s3.c
endif
if ENABLE_EROFS_MT
liberofs_la_LDFLAGS += -lpthread
liberofs_la_SOURCES += workqueue.c
endif
if OS_LINUX
liberofs_la_CFLAGS += ${libnl3_CFLAGS}
liberofs_la_SOURCES += backends/nbd.c
endif
if ENABLE_OCI
liberofs_la_SOURCES += remotes/oci.c
liberofs_la_CFLAGS += ${libcurl_CFLAGS} ${json_c_CFLAGS}
liberofs_la_LDFLAGS += ${libcurl_LIBS} ${json_c_LIBS}
endif
