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

src_libibverbs_la_SOURCES = src/cmd.c src/device.c src/init.c src/marshall.c \
			    src/memory.c src/verbs.c
src_libibverbs_la_LDFLAGS = -version-info 1 -export-dynamic \
    $(libibverbs_version_script)
src_libibverbs_la_DEPENDENCIES = $(srcdir)/src/libibverbs.map

bin_PROGRAMS = examples/ibv_devices examples/ibv_devinfo \
    examples/ibv_asyncwatch examples/ibv_rc_pingpong examples/ibv_uc_pingpong \
    examples/ibv_ud_pingpong examples/ibv_srq_pingpong
examples_ibv_devices_SOURCES = examples/device_list.c
examples_ibv_devices_LDADD = $(top_builddir)/src/libibverbs.la
examples_ibv_devinfo_SOURCES = examples/devinfo.c
examples_ibv_devinfo_LDADD = $(top_builddir)/src/libibverbs.la
examples_ibv_rc_pingpong_SOURCES = examples/rc_pingpong.c
examples_ibv_rc_pingpong_LDADD = $(top_builddir)/src/libibverbs.la
examples_ibv_uc_pingpong_SOURCES = examples/uc_pingpong.c
examples_ibv_uc_pingpong_LDADD = $(top_builddir)/src/libibverbs.la
examples_ibv_ud_pingpong_SOURCES = examples/ud_pingpong.c
examples_ibv_ud_pingpong_LDADD = $(top_builddir)/src/libibverbs.la
examples_ibv_srq_pingpong_SOURCES = examples/srq_pingpong.c
examples_ibv_srq_pingpong_LDADD = $(top_builddir)/src/libibverbs.la
examples_ibv_asyncwatch_SOURCES = examples/asyncwatch.c
examples_ibv_asyncwatch_LDADD = $(top_builddir)/src/libibverbs.la

libibverbsincludedir = $(includedir)/infiniband

libibverbsinclude_HEADERS = include/infiniband/arch.h include/infiniband/driver.h \
    include/infiniband/kern-abi.h include/infiniband/opcode.h include/infiniband/verbs.h \
    include/infiniband/sa-kern-abi.h include/infiniband/sa.h include/infiniband/marshall.h

man_MANS = man/ibv_asyncwatch.1 man/ibv_devices.1 man/ibv_devinfo.1 \
    man/ibv_rc_pingpong.1 man/ibv_uc_pingpong.1 man/ibv_ud_pingpong.1 \
    man/ibv_srq_pingpong.1

DEBIAN = debian/changelog debian/compat debian/control debian/copyright \
    debian/ibverbs-utils.install debian/libibverbs1.install \
    debian/libibverbs1.postinst debian/libibverbs-dev.install \
    debian/rules

EXTRA_DIST = include/infiniband/driver.h include/infiniband/kern-abi.h \
    include/infiniband/opcode.h include/infiniband/verbs.h src/ibverbs.h \
    include/infiniband/marshall.h include/infiniband/sa-kern-abi.h include/infiniband/sa.h \
    src/libibverbs.map libibverbs.spec.in $(man_MANS) $(DEBIAN)

dist-hook: libibverbs.spec
	cp libibverbs.spec $(distdir)
