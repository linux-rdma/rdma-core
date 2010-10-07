ACLOCAL_AMFLAGS = -I config
SUBDIRS = .

INCLUDES = -I$(srcdir)/include -I$(includedir)

lib_LTLIBRARIES = libibmad.la

libibmad_la_CFLAGS = -Wall

if HAVE_LD_VERSION_SCRIPT
libibmad_version_script = -Wl,--version-script=$(srcdir)/src/libibmad.map
else
libibmad_version_script =
endif

libibmad_la_SOURCES = src/dump.c src/fields.c src/mad.c src/portid.c \
		      src/resolve.c src/rpc.c src/sa.c src/smp.c src/gs.c \
		      src/serv.c src/register.c src/vendor.c src/bm.c \
		      src/mad_internal.h

libibmad_la_LDFLAGS = -version-info $(ibmad_api_version) \
    -export-dynamic $(libibmad_version_script)
libibmad_la_DEPENDENCIES = $(srcdir)/src/libibmad.map

libibmadincludedir = $(includedir)/infiniband

libibmadinclude_HEADERS = $(srcdir)/include/infiniband/mad.h $(srcdir)/include/infiniband/mad_osd.h

EXTRA_DIST = libibmad.spec.in libibmad.spec \
	$(srcdir)/src/libibmad.map libibmad.ver autogen.sh

dist-hook:
	if [ -x $(top_srcdir)/../gen_chlog.sh ] ; then \
		$(top_srcdir)/../gen_chlog.sh $(PACKAGE) > $(distdir)/ChangeLog ; \
	fi
