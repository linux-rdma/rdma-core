# $Id$

sbin_PROGRAMS = src/ibsrpdm srp_daemon/srp_daemon
man_MANS = man/ibsrpdm.1 man/srp_daemon.1

src_ibsrpdm_CFLAGS = -Wall
src_ibsrpdm_SOURCES = src/srp-dm.c

srp_daemon_srp_daemon_LDADD = -libumad -libcommon -libverbs -lpthread
srp_daemon_srp_daemon_CFLAGS = -Wall -I $(DESTDIR)$(includedir) -fno-strict-aliasing
srp_daemon_srp_daemon_SOURCES = srp_daemon/srp_daemon.c srp_daemon/srp_handle_traps.c srp_daemon/srp_sync.c

sbin_SCRIPTS = \
    srp_daemon/srp_daemon.sh \
    srp_daemon/run_srp_daemon

EXTRA_DIST = \
    srp_daemon/srp_daemon.h \
    srp_daemon/srp_ib_types.h \
    srp_daemon/srp_daemon.sh \
    srp_daemon/run_srp_daemon \
    src/srp-dm.h \
    src/ib_user_mad.h \
    srptools.spec.in $(man_MANS)

dist-hook: srptools.spec
	cp srptools.spec $(distdir)
