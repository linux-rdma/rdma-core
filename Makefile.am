INCLUDES = -I$(srcdir)/include

lib_LTLIBRARIES = src/librdmacm.la

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

src_librdmacm_la_CFLAGS = $(AM_CFLAGS)

if HAVE_LD_VERSION_SCRIPT
    librdmacm_version_script = -Wl,--version-script=$(srcdir)/src/librdmacm.map
else
    librdmacm_version_script =
endif

src_librdmacm_la_SOURCES = src/cma.c
src_librdmacm_la_LDFLAGS = -version-info 1 -export-dynamic \
			   $(librdmacm_version_script)
src_librdmacm_la_DEPENDENCIES =  $(srcdir)/src/librdmacm.map

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
			   include/rdma/rdma_cma.h

EXTRA_DIST = include/rdma/rdma_cma_abi.h include/rdma/rdma_cma.h \
	     src/librdmacm.map librdmacm.spec.in

dist-hook: librdmacm.spec
	cp librdmacm.spec $(distdir)
