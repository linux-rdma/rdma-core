lib_LTLIBRARIES = src/libcxgb4.la

AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DNDEBUG -DOVERFLOW_DETECTION

if HAVE_LD_VERSION_SCRIPT
    cxgb4_version_script = -Wl,--version-script=$(srcdir)/src/cxgb4.map
else
    cxgb4_version_script =
endif

src_libcxgb4_la_SOURCES = src/cq.c src/dev.c src/qp.c src/verbs.c src/sim.c
src_libcxgb4_la_LDFLAGS = -avoid-version \
			  -release @IBV_DEVICE_LIBRARY_EXTENSION@ \
			  $(cxgb4_version_script)

cxgb4confdir = $(sysconfdir)/libibverbs.d
cxgb4conf_DATA = cxgb4.driver

#DEBIAN = debian/changelog debian/compat debian/control debian/copyright \
#    debian/libcxgb41.install debian/libcxgb4-dev.install debian/rules

EXTRA_DIST = src/queue.h src/t4.h src/t4fw_interface.h src/t4_regs.h\
	     src/libcxgb4.h src/cxgb4-abi.h src/cxgb4.map libcxgb4.spec.in\
	     cxgb4.driver

dist-hook: libcxgb4.spec
	cp libcxgb4.spec $(distdir)
