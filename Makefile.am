# $Id$
INCLUDES = -I$(srcdir)/include

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

ibcmlibdir = $(libdir)

ibcmlib_LTLIBRARIES = src/libibcm.la

src_ibcm_la_CFLAGS = -g -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
    ibcm_version_script = -Wl,--version-script=$(srcdir)/src/libibcm.map
else
    ibcm_version_script =
endif

src_libibcm_la_SOURCES = src/cm.c
src_libibcm_la_LDFLAGS = -avoid-version $(ucm_version_script)

libibcmincludedir = $(includedir)/infiniband

libibcminclude_HEADERS = include/infiniband/cm_abi.h \
			 include/infiniband/cm.h

EXTRA_DIST = include/infiniband/cm_abi.h \
	     include/infiniband/cm.h \
	     src/libibcm.map \
	     libibcm.spec.in

dist-hook: libibcm.spec
	cp libibcm.spec $(distdir)
