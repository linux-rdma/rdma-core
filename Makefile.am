# $Id$

INCLUDES = -I$(srcdir)/include

lib_LTLIBRARIES = src/libibverbs.la

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

src_libibverbs_la_CFLAGS = -g -Wall -D_GNU_SOURCE -DDRIVER_PATH=\"$(libdir)/infiniband\"

if HAVE_LD_VERSION_SCRIPT
    libibverbs_version_script = -Wl,--version-script=$(srcdir)/src/libibverbs.map
else
    libibverbs_version_script =
endif

src_libibverbs_la_SOURCES = src/cmd.c src/device.c src/init.c src/memory.c src/verbs.c
src_libibverbs_la_LDFLAGS = -version-info 1 -export-dynamic \
    $(libibverbs_version_script)
src_libibverbs_la_DEPENDENCIES = $(srcdir)/src/libibverbs.map

bin_PROGRAMS = examples/ibv_devices examples/ibv_asyncwatch \
    examples/ibv_pingpong examples/ibv_ud_pingpong
examples_ibv_devices_SOURCES = examples/device_list.c
examples_ibv_devices_LDADD = $(top_builddir)/src/libibverbs.la
examples_ibv_pingpong_SOURCES = examples/pingpong.c
examples_ibv_pingpong_LDADD = $(top_builddir)/src/libibverbs.la
examples_ibv_ud_pingpong_SOURCES = examples/ud-pingpong.c
examples_ibv_ud_pingpong_LDADD = $(top_builddir)/src/libibverbs.la
examples_ibv_asyncwatch_SOURCES = examples/asyncwatch.c
examples_ibv_asyncwatch_LDADD = $(top_builddir)/src/libibverbs.la

libibverbsincludedir = $(includedir)/infiniband

libibverbsinclude_HEADERS = include/infiniband/arch.h include/infiniband/driver.h \
    include/infiniband/kern-abi.h include/infiniband/opcode.h include/infiniband/verbs.h

EXTRA_DIST = include/infiniband/driver.h include/infiniband/kern-abi.h \
    include/infiniband/opcode.h include/infiniband/verbs.h \
    src/ibverbs.h \
    src/libibverbs.map \
    libibverbs.spec.in

dist-hook: libibverbs.spec
	cp libibverbs.spec $(distdir)
