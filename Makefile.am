# $Id$

AM_CFLAGS = -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter

sbin_PROGRAMS = src/ibsrpdm srp_daemon/srp_daemon 
man_MANS = man/ibsrpdm.1 man/srp_daemon.1

src_ibsrpdm_SOURCES = src/srp-dm.c
src_ibsrpdm_CFLAGS = $(AM_CFLAGS) -fno-strict-aliasing

srp_daemon_srp_daemon_LDADD = -libumad -libverbs -lpthread
srp_daemon_srp_daemon_CFLAGS = $(AM_CFLAGS) -I $(DESTDIR)$(includedir) \
	-fno-strict-aliasing
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
