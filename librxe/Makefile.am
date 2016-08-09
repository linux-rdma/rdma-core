AM_CFLAGS = -g -Wall
  
rxe_version_script = @RXE_VERSION_SCRIPT@

RXE_SOURCES = src/rxe.c
  
if HAVE_IBV_DEVICE_LIBRARY_EXTENSION
    lib_LTLIBRARIES = src/librxe.la
    src_librxe_la_SOURCES = $(RXE_SOURCES)
    src_librxe_la_LDFLAGS = -avoid-version -release @IBV_DEVICE_LIBRARY_EXTENSION@ \
	$(rxe_version_script)
    rxeconfdir = $(sysconfdir)/libibverbs.d
    rxeconf_DATA = rxe.driver
else
    rxelibdir = $(libdir)/infiniband
    rxelib_LTLIBRARIES = src/rxe.la
    src_rxe_la_SOURCES = $(RXE_SOURCES)
    src_rxe_la_LDFLAGS = -avoid-version -module $(rxe_version_script)
endif

dist_man_MANS = man/rxe.7 \
		man/rxe_cfg.8

dist_bin_SCRIPTS = rxe_cfg

EXTRA_DIST = \
	src/rxe.h \
	src/rxe-abi.h \
	src/rxe_queue.h \
	src/rxe.map \
	librxe.spec.in \
	rxe.driver

dist-hook: librxe.spec
	cp librxe.spec $(distdir)

