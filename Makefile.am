# $Id$

mthcalibdir = $(libdir)/infiniband

mthcalib_LTLIBRARIES = src/mthca.la

src_mthca_la_CFLAGS = -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
    mthca_version_script = -Wl,--version-script=$(srcdir)/src/mthca.map
else
    mthca_version_script =
endif

src_mthca_la_SOURCES = src/ah.c src/cq.c src/memfree.c src/mthca.c src/qp.c src/verbs.c
src_mthca_la_LDFLAGS = -avoid-version -module \
    $(mthca_version_script)

DEBIAN = debian/changelog debian/compat debian/control debian/copyright \
    debian/libmthca1.install debian/libmthca-dev.install debian/rules

EXTRA_DIST = src/doorbell.h src/mthca.h src/mthca-abi.h src/mthca.map \
    libmthca.spec.in $(DEBIAN)

dist-hook: libmthca.spec
	cp libmthca.spec $(distdir)
