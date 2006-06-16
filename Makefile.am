# $Id: Makefile.am 3373 2005-09-12 16:34:20Z roland $
INCLUDES = -I$(srcdir)/include

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

rdmacmlibdir = $(libdir)

rdmacmlib_LTLIBRARIES = src/librdmacm.la

src_rdmacm_la_CFLAGS = -g -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
    rdmacm_version_script = -Wl,--version-script=$(srcdir)/src/librdmacm.map
else
    rdmacm_version_script =
endif

src_librdmacm_la_SOURCES = src/cma.c
src_librdmacm_la_LDFLAGS = -avoid-version $(rdmacm_version_script)

bin_PROGRAMS = examples/ucmatose examples/rping examples/udaddy examples/mckey
examples_ucmatose_SOURCES = examples/cmatose.c
examples_ucmatose_LDADD = $(top_builddir)/src/librdmacm.la
examples_rping_SOURCES = examples/rping.c
examples_rping_LDADD = $(top_builddir)/src/librdmacm.la
examples_udaddy_SOURCES = examples/udaddy.c
examples_udaddy_LDADD = $(top_builddir)/src/librdmacm.la
examples_mckey_SOURCES = examples/mckey.c
examples_mckey_LDADD = $(top_builddir)/src/librdmacm.la

librdmacmincludedir = $(includedir)/rdma

librdmacminclude_HEADERS = include/rdma/rdma_cma_abi.h \
			   include/rdma/rdma_cma.h \
			   include/rdma/rdma_cma_ib.h

EXTRA_DIST = include/rdma/rdma_cma_abi.h \
	     include/rdma/rdma_cma.h \
	     include/rdma/rdma_cma_ib.h \
	     src/librdmacm.map \
	     librdmacm.spec.in

dist-hook: librdmacm.spec
	cp librdmacm.spec $(distdir)
