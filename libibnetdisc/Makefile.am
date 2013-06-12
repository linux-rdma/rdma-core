
#SUBDIRS = .

INCLUDES = -I$(srcdir)/include -I$(includedir) -I$(includedir)/infiniband

lib_LTLIBRARIES = libibnetdisc.la
sbin_PROGRAMS =

if ENABLE_TEST_UTILS
sbin_PROGRAMS += test/testleaks
endif

if DEBUG
DBGFLAGS = -ggdb -D_DEBUG_
else
DBGFLAGS =
endif

if HAVE_LD_VERSION_SCRIPT
libibnetdisc_version_script = -Wl,--version-script=$(srcdir)/src/libibnetdisc.map
else
libibnetdisc_version_script =
endif

libibnetdisc_la_SOURCES = src/ibnetdisc.c src/ibnetdisc_cache.c src/chassis.c \
			  src/chassis.h src/internal.h src/query_smp.c
libibnetdisc_la_CFLAGS = -Wall $(DBGFLAGS) $(GLIB_CFLAGS)
libibnetdisc_la_LDFLAGS = -version-info $(ibnetdisc_api_version) \
	-export-dynamic $(libibnetdisc_version_script) \
	-libmad $(GLIB_LIBS)
libibnetdisc_la_DEPENDENCIES = $(srcdir)/src/libibnetdisc.map

libibnetdiscincludedir = $(includedir)/infiniband

test_testleaks_SOURCES = test/testleaks.c
test_testleaks_CFLAGS = -Wall $(DBGFLAGS)
test_testleaks_LDFLAGS = -libnetdisc
test_testleaks_DEPENDENCIES = libibnetdisc.la

libibnetdiscinclude_HEADERS = $(srcdir)/include/infiniband/ibnetdisc.h \
				$(srcdir)/include/infiniband/ibnetdisc_osd.h

man_MANS = man/ibnd_debug.3 \
	man/ibnd_destroy_fabric.3 \
	man/ibnd_discover_fabric.3 \
	man/ibnd_find_node_dr.3 \
	man/ibnd_find_node_guid.3 \
	man/ibnd_iter_nodes.3 \
	man/ibnd_iter_nodes_type.3 \
	man/ibnd_show_progress.3

EXTRA_DIST = $(srcdir)/src/libibnetdisc.map libibnetdisc.ver $(man_MANS)

