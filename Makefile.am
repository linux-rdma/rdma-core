# $Id$

sbin_PROGRAMS = src/ibsrpdm srp_daemon/srp_daemon emulate_udev/srp_post_multipath emulate_udev/srp_dm_multipath_daemon
man_MANS = man/ibsrpdm.1 man/srp_daemon.1

src_ibsrpdm_CFLAGS = -Wall
src_ibsrpdm_SOURCES = src/srp-dm.c

srp_daemon_srp_daemon_LDADD = -libumad -libcommon -libverbs -lpthread
srp_daemon_srp_daemon_CFLAGS = -Wall -I $(DESTDIR)$(includedir) -fno-strict-aliasing
srp_daemon_srp_daemon_SOURCES = srp_daemon/srp_daemon.c srp_daemon/srp_handle_traps.c srp_daemon/srp_sync.c

emulate_udev_srp_post_multipath_CFLAGS = -Wall 
emulate_udev_srp_post_multipath_SOURCES = emulate_udev/srp_post_multipath.c

emulate_udev_srp_dm_multipath_daemon_CFLAGS = -Wall 
emulate_udev_srp_dm_multipath_daemon_SOURCES = emulate_udev/srp_dm_multipath_daemon.c

sbin_SCRIPTS = \
    srp_daemon/srp_daemon.sh \
    srp_daemon/run_srp_daemon \
    emulate_udev/execute_multipath_or_kpartx.sh \
    emulate_udev/srp_dnotify \
    emulate_udev/start_srp_dnotify.sh

EXTRA_DIST = \
    srp_daemon/srp_daemon.h \
    srp_daemon/srp_ib_types.h \
    srp_daemon/srp_daemon.sh \
    srp_daemon/run_srp_daemon \
    src/srp-dm.h \
    src/ib_user_mad.h \
    emulate_udev/execute_multipath_or_kpartx.sh \
    emulate_udev/start_srp_dnotify.sh \
    srptools.spec.in $(man_MANS)

dist-hook: srptools.spec
	cp srptools.spec $(distdir)
