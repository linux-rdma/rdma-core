# $Id$
INCLUDES = -I$(srcdir)/include

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

ibcmlibdir = $(libdir)/infiniband

ibcmlib_LTLIBRARIES = src/ibcm.la

src_ibcm_la_CFLAGS = -g -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
    ibcm_version_script = -Wl,--version-script=$(srcdir)/src/libibcm.map
else
    ibcm_version_script =
endif

src_ibcm_la_SOURCES = src/cm.c
src_ibcm_la_LDFLAGS = -avoid-version -module $(ucm_version_script)

libibcmincludedir = $(includedir)/infiniband

libibcminclude_HEADERS = include/infiniband/cm_abi.h \
			 include/infiniband/cm.h \
			 include/infiniband/sa.h

EXTRA_DIST = include/infiniband/cm_abi.h \
	     include/infiniband/cm.h \
	     include/infiniband/sa.h \
	     src/libibcm.map \
	     libibverbs.spec.in

dist-hook: libibcm.spec
	cp libibcm.spec $(distdir)
