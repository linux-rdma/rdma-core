
lib_LTLIBRARIES = src/libocrdma.la

AM_CFLAGS = -Wall

if HAVE_LD_VERSION_SCRIPT
    ocrdma_version_script = -Wl,--version-script=$(srcdir)/src/ocrdma.map
else
    ocrdma_version_script =
endif

src_libocrdma_la_SOURCES = src/ocrdma_main.c src/ocrdma_verbs.c
src_libocrdma_la_LDFLAGS = -avoid-version -module -release @IBV_DEVICE_LIBRARY_EXTENSION@\
    $(ocrdma_version_script)

ocrdmaconfdir = $(sysconfdir)/libibverbs.d
ocrdmaconf_DATA = ocrdma.driver

EXTRA_DIST = src/ocrdma.map src/ocrdma_main.h src/ocrdma_abi.h \
             src/ocrdma_list.h libocrdma.spec.in ocrdma.driver

dist-hook: libocrdma.spec
	cp libocrdma.spec $(distdir)
