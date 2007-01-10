# $Id: Makefile.am 3802 2005-10-18 18:32:06Z tom $

lib_LTLIBRARIES = src/libcxgb3.la

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
    cxgb3_version_script = -Wl,--version-script=$(srcdir)/src/iwch.map
else
    cxgb3_version_script =
endif

src_libcxgb3_la_SOURCES = src/cq.c src/iwch.c src/qp.c \
    src/verbs.c
src_libcxgb3_la_LDFLAGS = -avoid-version -release @IBV_DEVICE_LIBRARY_EXTENSION@ \
    $(cxgb3_version_script)

cxgb3confdir = $(sysconfdir)/libibverbs.d
cxgb3conf_DATA = cxgb3.driver
#DEBIAN = debian/changelog debian/compat debian/control debian/copyright \
#    debian/libcxgb31.install debian/libcxgb3-dev.install debian/rules

EXTRA_DIST = src/firmware_exports.h src/cxio_wr.h src/iwch.h src/iwch-abi.h \
     src/iwch.map libcxgb3.spec.in cxgb3.driver

dist-hook: libcxgb3.spec
	cp libcxgb3.spec $(distdir)
