# $Id$

INCLUDES = -I$(srcdir)/include

lib_LTLIBRARIES = src/libibverbs.la

src_libibverbs_la_CFLAGS = -Wall -D_GNU_SOURCE -DDRIVER_PATH=\"$(libdir)/infiniband\"

if HAVE_LD_VERSION_SCRIPT
    libibverbs_version_script = -Wl,--version-script=$(srcdir)/src/libibverbs.map
else
    libibverbs_version_script =
endif

src_libibverbs_la_SOURCES = src/init.c src/device.c src/memory.c
src_libibverbs_la_LDFLAGS = -version-info 1 -export-dynamic \
    $(libibverbs_version_script)
src_libibverbs_la_DEPENDENCIES = $(srcdir)/src/libibverbs.map

bin_PROGRAMS = examples/ib_devices
examples_ib_devices_SOURCES = examples/device_list.c
examples_ib_devices_LDADD = $(top_builddir)/src/libibverbs.la

libibverbsincludedir = $(includedir)/infiniband

libibverbsinclude_HEADERS = include/infiniband/verbs.h include/infiniband/driver.h

EXTRA_DIST = include/infiniband/verbs.h include/infiniband/driver.h \
    libibverbs.spec.in

dist-hook: libibverbs.spec
	cp libibverbs.spec $(distdir)
