AM_CPPFLAGS = -I$(srcdir)/include -I$(includedir)/libnl3 -I/usr/include/libnl3
AM_CFLAGS = -g -O2 -Wall -D_GNU_SOURCE
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = src/iwpmd
src_iwpmd_SOURCES = src/iwarp_pm_server.c src/iwarp_pm_common.c src/iwarp_pm_helper.c

	mkdir -p $(includedir)/rdma/
libiwpmdir = $(includedir)/rdma/
libiwpm_HEADERS = $(srcdir)/include/iwpm_netlink.h $(srcdir)/include/iwarp_pm.h

EXTRA_DIST = iwpmd_init

dist-hook: libiwpm.spec
	cp libiwpm.spec $(distdir)
