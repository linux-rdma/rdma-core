
lib_LTLIBRARIES = src/libnes.la

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
    nes_version_script = -Wl,--version-script=$(srcdir)/src/nes.map
else
    nes_version_script =
endif

src_libnes_la_SOURCES = src/nes_umain.c src/nes_uverbs.c
src_libnes_la_LDFLAGS = -avoid-version -module -release @IBV_DEVICE_LIBRARY_EXTENSION@\
    $(nes_version_script)

nesconfdir = $(sysconfdir)/libibverbs.d
nesconf_DATA = nes.driver

#DEBIAN = debian/changelog debian/compat debian/control debian/copyright \
#    debian/libnes1.install debian/libnes-dev.install debian/rules

EXTRA_DIST = src/nes-abi.h src/nes_umain.h \
    src/nes.map libnes.spec.in nes.driver $(DEBIAN)

dist-hook: libnes.spec
	cp libnes.spec $(distdir)
