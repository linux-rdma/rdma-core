# $Id$

SUBDIRS = .

INCLUDES = -I$(srcdir)/include/infiniband \
	   -I$(srcdir)/../libibcommon/include/infiniband

lib_LTLIBRARIES = libibumad.la

libibumad_la_CFLAGS = -Wall

if HAVE_LD_VERSION_SCRIPT
    libibumad_version_script = -Wl,--version-script=$(srcdir)/src/libibumad.map
else
    libibumad_version_script =
endif

libibumad_la_SOURCES = src/umad.c
libibumad_la_LDFLAGS = -version-info 1 -export-dynamic \
    $(libibumad_version_script)
libibumad_la_DEPENDENCIES = $(srcdir)/src/libibumad.map

libibumadincludedir = $(includedir)/infiniband

libibumadinclude_HEADERS = $(srcdir)/include/infiniband/umad.h

EXTRA_DIST = $(srcdir)/include/infiniband/umad.h libibumad.spec.in \
	     $(srcdir)/src/libibumad.map

dist-hook: libibumad.spec
	cp libibumad.spec $(distdir)
