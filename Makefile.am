# $Id: Makefile.am 3802 2005-10-18 18:32:06Z tom $

cxgb3libdir = $(libdir)/infiniband

cxgb3lib_LTLIBRARIES = src/cxgb3.la

src_cxgb3_la_CFLAGS = -g -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
    cxgb3_version_script = -Wl,--version-script=$(srcdir)/src/iwch.map
else
    cxgb3_version_script =
endif

src_cxgb3_la_SOURCES = src/cq.c src/iwch.c src/qp.c \
    src/verbs.c
src_cxgb3_la_LDFLAGS = -avoid-version -module \
    $(cxgb3_version_script)

#DEBIAN = debian/changelog debian/compat debian/control debian/copyright \
#    debian/libcxgb31.install debian/libcxgb3-dev.install debian/rules

EXTRA_DIST = src/firmware_exports.h src/cxio_wr.h src/iwch.h src/iwch-abi.h \
    src/iwch.map libcxgb3.spec.in $(DEBIAN)

dist-hook: libcxgb3.spec
	cp libcxgb3.spec $(distdir)
