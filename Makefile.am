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
    emulate_udev/execute_multipath_or_kpartx.sh 

EXTRA_DIST = \
    srp_daemon/srp_daemon.h \
    srp_daemon/srp_ib_types.h \
    srp_daemon/srp_daemon.sh \
    srp_daemon/run_srp_daemon \
    src/srp-dm.h \
    src/ib_user_mad.h \
    emulate_udev/execute_multipath_or_kpartx.sh \
    emulate_udev/srp_dm_multipath_daemon.h \
    srp_daemon/srp_daemon.conf \
    srptools.spec.in $(man_MANS)

dist-hook: srptools.spec
	cp srptools.spec $(distdir)

install-data-hook:
	if test -e $(DESTDIR)/etc/srp_daemon.conf; then \
		diff -q $(srcdir)/srp_daemon/srp_daemon.conf \
			$(DESTDIR)/etc/srp_daemon.conf 1> /dev/null; \
		if test $$? == 1; then \
			t=$(shell date +'%Y%m%d%H%M%S'); \
			cp -p $(srcdir)/srp_daemon/srp_daemon.conf \
			      $(DESTDIR)/etc/srp_daemon.conf.$$t; \
			echo "NOTE: existing srp_daemon.conf was not updated."; \
			echo "      srp_daemon.conf installed as srp_daemon.conf.$$t instead."; \
		fi; \
	else \
		if test ! -d $(DESTDIR)/etc; then \
			mkdir -p $(DESTDIR)/etc; \
		fi; \
		cp -p $(srcdir)/srp_daemon/srp_daemon.conf $(DESTDIR)/etc; \
	fi
