AM_CPPFLAGS = -I$(includedir)/libnl3 -I/usr/include/libnl3
AM_CFLAGS = -g -O2 -Wall -D_GNU_SOURCE
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = src/iwpmd
src_iwpmd_SOURCES = src/iwarp_pm_server.c src/iwarp_pm_common.c src/iwarp_pm_helper.c src/iwpm_netlink.h src/iwarp_pm.h

EXTRA_DIST = iwpmd_init iwpmd.service

dist-hook: iwpmd.spec
	cp iwpmd.spec $(distdir)
