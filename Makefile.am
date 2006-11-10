# $Id$

mthcalibdir = $(libdir)/infiniband

mthcalib_LTLIBRARIES = src/mthca.la

src_mthca_la_CFLAGS = -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
    mthca_version_script = -Wl,--version-script=$(srcdir)/src/mthca.map
else
    mthca_version_script =
endif

src_mthca_la_SOURCES = src/mthca.c
src_mthca_la_LDFLAGS = -avoid-version -module \
    $(mthca_version_script)

EXTRA_DIST = libmthca.spec.in

dist-hook: libmthca.spec
	cp libmthca.spec $(distdir)
