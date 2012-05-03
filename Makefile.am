ACLOCAL_AMFLAGS = -I config
SUBDIRS = libibnetdisc

INCLUDES = -I$(top_builddir)/include/ -I$(srcdir)/include -I$(includedir) \
	-I$(includedir)/infiniband -I$(top_srcdir)/libibnetdisc/include

if DEBUG
DBGFLAGS = -ggdb -D_DEBUG_
else
DBGFLAGS =
endif

sbin_PROGRAMS = src/ibaddr src/ibnetdiscover src/ibping src/ibportstate \
	        src/ibroute src/ibstat src/ibsysstat src/ibtracert \
	        src/perfquery src/sminfo src/smpdump src/smpquery \
	        src/saquery src/vendstat src/iblinkinfo \
		src/ibqueryerrors src/ibcacheedit src/ibccquery \
		src/ibccconfig

if ENABLE_TEST_UTILS
sbin_PROGRAMS += src/ibsendtrap src/mcm_rereg_test
endif

sbin_SCRIPTS = scripts/ibhosts \
		scripts/ibswitches scripts/ibnodes scripts/ibrouters \
		scripts/ibfindnodesusing.pl scripts/ibidsverify.pl \
		scripts/check_lft_balance.pl \
		scripts/dump_lfts.sh scripts/dump_mfts.sh \
		scripts/ibstatus

if ENABLE_COMPAT_UTILS
sbin_SCRIPTS += scripts/ibcheckerrs scripts/ibchecknet scripts/ibchecknode \
		scripts/ibcheckport scripts/ibcheckportwidth scripts/ibcheckportstate \
		scripts/ibcheckwidth scripts/ibcheckstate \
		scripts/ibcheckerrors scripts/ibdatacounts \
		scripts/ibdatacounters scripts/ibdiscover.pl \
		scripts/ibswportwatch.pl \
		scripts/ibqueryerrors.pl scripts/iblinkinfo.pl \
		scripts/ibprintca.pl scripts/ibprintswitch.pl scripts/ibprintrt.pl \
		scripts/set_nodedesc.sh scripts/ibclearerrors scripts/ibclearcounters
endif

man_MANS = man/check_lft_balance.8 man/ibcacheedit.8 \
		man/ibstatus.8 \
		doc/man/ibaddr.8 \
		doc/man/ibccconfig.8 \
		doc/man/ibccquery.8 \
		doc/man/dump_lfts.8 \
		doc/man/dump_mfts.8 \
		doc/man/iblinkinfo.8 \
		doc/man/ibfindnodesusing.8 \
		doc/man/ibhosts.8 \
		doc/man/ibnetdiscover.8 \
		doc/man/ibnodes.8 \
		doc/man/ibping.8 \
		doc/man/ibportstate.8 \
		doc/man/ibqueryerrors.8 \
		doc/man/ibroute.8 \
		doc/man/ibrouters.8 \
		doc/man/ibstat.8 \
		doc/man/ibswitches.8 \
		doc/man/ibsysstat.8 \
		doc/man/ibtracert.8 \
		doc/man/perfquery.8 \
		doc/man/saquery.8 \
		doc/man/sminfo.8 \
		doc/man/smpdump.8 \
		doc/man/smpquery.8 \
		doc/man/vendstat.8 \
		doc/man/infiniband-diags.8 \
		man/ibidsverify.8

# define this for the dist target
compat_man_pages = man/ibdiscover.8 man/ibcheckerrors.8 man/ibcheckerrs.8 \
		man/ibchecknet.8 man/ibchecknode.8 man/ibcheckport.8 \
		man/ibcheckportstate.8 man/ibcheckportwidth.8 \
		man/ibcheckstate.8 man/ibcheckwidth.8 \
		man/ibswportwatch.8 \
		man/ibprintswitch.8 man/ibprintca.8 man/ibdatacounts.8 \
		man/ibdatacounters.8 man/ibprintrt.8 \
		man/ibclearcounters.8 man/ibclearerrors.8

# but only actually install them if specified
if ENABLE_COMPAT_UTILS
man_MANS += $(compat_man_pages)
endif

noinst_LIBRARIES = libcommon.a

AM_CFLAGS = -Wall $(DBGFLAGS)
LDADD = libcommon.a

libcommon_a_SOURCES = src/ibdiag_common.c
src_ibaddr_SOURCES = src/ibaddr.c
src_ibnetdiscover_SOURCES = src/ibnetdiscover.c
src_ibnetdiscover_LDFLAGS = -L$(top_builddir)/libibnetdisc -libnetdisc
src_ibping_SOURCES = src/ibping.c
src_ibportstate_SOURCES = src/ibportstate.c
src_ibroute_SOURCES = src/ibroute.c
src_ibstat_SOURCES = src/ibstat.c
src_ibsysstat_SOURCES = src/ibsysstat.c
src_ibtracert_SOURCES = src/ibtracert.c
src_perfquery_SOURCES = src/perfquery.c
src_sminfo_SOURCES = src/sminfo.c
src_smpdump_SOURCES = src/smpdump.c
src_smpquery_SOURCES = src/smpquery.c
src_saquery_SOURCES = src/saquery.c
src_ibsendtrap_SOURCES = src/ibsendtrap.c
src_vendstat_SOURCES = src/vendstat.c
src_mcm_rereg_test_SOURCES = src/mcm_rereg_test.c
src_iblinkinfo_SOURCES = src/iblinkinfo.c
src_ibccquery_SOURCES = src/ibccquery.c
src_ibccconfig_SOURCES = src/ibccconfig.c
src_iblinkinfo_LDFLAGS = -L$(top_builddir)/libibnetdisc -libnetdisc
src_ibqueryerrors_SOURCES = src/ibqueryerrors.c
src_ibqueryerrors_LDFLAGS = -L$(top_builddir)/libibnetdisc -libnetdisc
src_ibcacheedit_SOURCES = src/ibcacheedit.c
src_ibcacheedit_LDFLAGS = -L$(top_builddir)/libibnetdisc -libnetdisc

BUILT_SOURCES = ibdiag_version
ibdiag_version:
	if [ -x $(top_srcdir)/gen_ver.sh ] ; then \
		ver_file=$(top_builddir)/include/ibdiag_version.h ; \
		ibdiag_ver=`cat $$ver_file | sed -ne '/#define IBDIAG_VERSION /s/^.*\"\(.*\)\"$$/\1/p'` ; \
		ver=`$(top_srcdir)/gen_ver.sh $(PACKAGE)` ; \
		if [ $$ver != $$ibdiag_ver ] ; then \
			cat $$ver_file | sed -e '/#define IBDIAG_VERSION /s/\".*\"/\"'$$ver'\"/' > tmp_new_version ; \
			cat tmp_new_version > $$ver_file && rm -f tmp_new_version ; \
		fi ; \
	fi

EXTRA_DIST = doc scripts include infiniband-diags.spec.in infiniband-diags.spec \
	$(man_MANS) $(compat_man_pages) autogen.sh etc/*

distclean-local:
	$(top_srcdir)/doc/generate clean

dist-hook:
	if [ -x $(top_srcdir)/gen_chlog.sh ] ; then \
		$(top_srcdir)/gen_chlog.sh > $(distdir)/ChangeLog ; \
	fi

# install this to a default location.
install-data-hook:
	if test ! -d $(DESTDIR)/$(sysconfdir)/infiniband-diags; then \
		$(top_srcdir)/config/install-sh -m 755 -d $(DESTDIR)/$(sysconfdir)/infiniband-diags; \
	fi
	$(top_srcdir)/config/install-sh -c -m 444 $(top_srcdir)/scripts/IBswcountlimits.pm $(DESTDIR)/$(PERL_INSTALLDIR)/IBswcountlimits.pm
	$(top_srcdir)/config/install-sh -c -m 444 $(top_srcdir)/etc/error_thresholds $(DESTDIR)/$(sysconfdir)/infiniband-diags
	$(top_srcdir)/config/install-sh -c -m 444 $(top_srcdir)/etc/ibdiag.conf $(DESTDIR)/$(sysconfdir)/infiniband-diags
