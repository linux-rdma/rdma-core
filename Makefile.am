
SUBDIRS = .

INCLUDES = -I$(srcdir)/include/infiniband \
	   -I$(srcdir)/../libibcommon/include/infiniband

man_MANS = man/umad_debug.3 man/umad_get_ca.3 \
	   man/umad_get_ca_portguids.3 man/umad_get_cas_names.3 \
	   man/umad_get_mad.3 man/umad_get_port.3 man/umad_init.3

lib_LTLIBRARIES = libibumad.la

libibumad_la_CFLAGS = -Wall

if HAVE_LD_VERSION_SCRIPT
libibumad_version_script = -Wl,--version-script=$(srcdir)/src/libibumad.map
else
libibumad_version_script =
endif

libibumad_la_SOURCES = src/umad.c
libibumad_la_LDFLAGS = -version-info $(ibumad_api_version) \
    -export-dynamic $(libibumad_version_script)
libibumad_la_DEPENDENCIES = $(srcdir)/src/libibumad.map

libibumadincludedir = $(includedir)/infiniband

libibumadinclude_HEADERS = $(srcdir)/include/infiniband/umad.h

EXTRA_DIST = $(srcdir)/include/infiniband/umad.h libibumad.spec.in \
	     $(srcdir)/src/libibumad.map libibumad.ver \
	     $(man_MANS)

dist-hook: libibumad.spec
	cp libibumad.spec $(distdir)

install-data-hook:
	cd $(DESTDIR)$(mandir)/man3 && \
	$(RM) umad_done.3 && \
	$(RM) umad_release_ca.3 && \
	$(RM) umad_release_port.3 && \
	$(LN_S) umad_init.3 umad_done.3 && \
	$(LN_S) umad_get_ca.3 umad_release_ca.3 && \
	$(LN_S) umad_get_port.3 umad_release_port.3
