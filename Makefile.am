# $Id$

AM_CFLAGS = -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter

sbin_PROGRAMS = srp_daemon/srp_daemon 
man_MANS = man/ibsrpdm.1 man/srp_daemon.1

srp_daemon_srp_daemon_LDADD = -libumad -libverbs -lpthread
srp_daemon_srp_daemon_CFLAGS = $(AM_CFLAGS) -I $(DESTDIR)$(includedir) \
	-fno-strict-aliasing
srp_daemon_srp_daemon_SOURCES = srp_daemon/srp_daemon.c srp_daemon/srp_handle_traps.c srp_daemon/srp_sync.c


sbin_SCRIPTS = \
    srp_daemon/srp_daemon.sh

EXTRA_DIST = \
    srp_daemon/srp_daemon.h \
    srp_daemon/srp_ib_types.h \
    srp_daemon/srp_daemon.sh \
    srp_daemon/srpd.in \
    srp_daemon/logrotate-srp_daemon \
    srp_daemon/rsyslog-srp_daemon.conf \
    srp_daemon/srp_daemon.conf \
    srptools.spec.in $(man_MANS)

dist-hook: srptools.spec
	cp srptools.spec $(distdir)

install-exec-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/init.d
	@INSTALL_PROGRAM@ srp_daemon/srpd $(DESTDIR)$(sysconfdir)/init.d/srpd
	if test -e $(DESTDIR)$(sbindir)/ibsrpdm; then	\
	    rm -f $(DESTDIR)$(sbindir)/ibsrpdm;		\
	fi;						\
	cd $(DESTDIR)$(sbindir) && ln -s srp_daemon ibsrpdm
# Backward compatability for DDN supplied srptools package
	if test -e $(DESTDIR)$(sbindir)/run_srp_daemon; then	\
	    rm -f $(DESTDIR)$(sbindir)/run_srp_daemon;		\
	fi;							\
	cd $(DESTDIR)$(sbindir) && ln -s srp_daemon run_srp_daemon

install-data-hook:
	if test -e $(DESTDIR)$(sysconfdir)/srp_daemon.conf; then	\
	    diff -q $(srcdir)/srp_daemon/srp_daemon.conf		\
	        $(DESTDIR)$(sysconfdir)/srp_daemon.conf 1>/dev/null;	\
	    if test $$? == 1; then					\
		t=$(shell date +'%Y%m%d%H%M%S');			\
		@INSTALL_DATA@ $(srcdir)/srp_daemon/srp_daemon.conf	\
		      $(DESTDIR)$(sysconfdir)/srp_daemon.conf.$$t;	\
		echo "NOTE: existing srp_daemon.conf was not updated.";	\
		echo "      srp_daemon.conf installed as"		\
		     "srp_daemon.conf.$$t instead.";			\
	    fi;								\
	else								\
	    mkdir -p $(DESTDIR)$(sysconfdir);				\
	    @INSTALL_DATA@ $(srcdir)/srp_daemon/srp_daemon.conf		\
		  $(DESTDIR)$(sysconfdir);				\
	fi
	mkdir -p $(DESTDIR)$(sysconfdir)/logrotate.d
	@INSTALL_DATA@ $(srcdir)/srp_daemon/logrotate-srp_daemon	\
	$(DESTDIR)$(sysconfdir)/logrotate.d/srp_daemon
	mkdir -p $(DESTDIR)$(sysconfdir)/rsyslog.d
	@INSTALL_DATA@ $(srcdir)/srp_daemon/rsyslog-srp_daemon.conf	\
	$(DESTDIR)$(sysconfdir)/rsyslog.d/srp_daemon.conf

rpm:
	name=@PACKAGE@ &&						 \
	version=@VERSION@ &&						 \
	rpmtopdir="$$(if [ $$(id -u) = 0 ]; then echo /usr/src/packages; \
		      else echo $$PWD/rpmbuilddir; fi)" &&		 \
	make dist-gzip &&						 \
	rm -rf $${rpmtopdir} &&						 \
	mkdir -p $${rpmtopdir}/{BUILD,RPMS,SOURCES,SPECS,SRPMS} &&	 \
	cp $${name}-$${version}.tar.gz $${rpmtopdir}/SOURCES &&		 \
	rpmbuild --define="%_topdir $${rpmtopdir}" -ba $${name}.spec

deb:
	./build-deb.sh ${TARGET}
