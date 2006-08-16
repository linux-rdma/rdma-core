# $Id: Makefile.am,v 1.2 2006/08/14 15:50:46 ishai Exp $

sbin_PROGRAMS = srp_daemon

srp_daemon_LDADD = -libumad -libcommon -libverbs
srp_daemon_CFLAGS = -g -Wall -I $(DESTDIR)$(includedir)
srp_daemon_SOURCES = srp_daemon.c srp_handle_traps.c srp_sync.c

EXTRA_DIST = \
    srp_daemon.h \
    srp_ib_types.h

