AM_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/linux -I$(srcdir)/src

AM_CFLAGS = -g -Wall -D_GNU_SOURCE 

if HAVE_LD_VERSION_SCRIPT
    libibacmp_version_script = -Wl,--version-script=$(srcdir)/prov/acmp/src/libibacmp.map
else
    libibacmp_version_script =
endif

bin_PROGRAMS = util/ib_acme
sbin_PROGRAMS = svc/ibacm
svc_ibacm_SOURCES = src/acm.c src/acm_util.c
util_ib_acme_SOURCES = src/acme.c src/libacm.c linux/libacm_linux.c src/parse.c
svc_ibacm_CFLAGS = $(AM_CFLAGS)
svc_ibacm_LDFLAGS = -rdynamic
util_ib_acme_CFLAGS = $(AM_CFLAGS) -DACME_PRINTS

pkglib_LTLIBRARIES = lib/libibacmp.la
lib_libibacmp_la_CFLAGS = $(AM_CFLAGS) 
lib_libibacmp_la_SOURCES = prov/acmp/src/acmp.c  
lib_libibacmp_la_LDFLAGS = -version-info 1 -export-dynamic \
			   $(libibacmp_version_script)
lib_libibacmp_la_DEPENDENCIES =  $(srcdir)/prov/acmp/src/libibacmp.map

ibacmincludedir = $(includedir)/infiniband

ibacminclude_HEADERS = include/infiniband/acm.h include/infiniband/acm_prov.h

libibacmpincludedir = $(includedir)/infiniband
libibacmpinclude_HEADERS = include/infiniband/acm.h include/infiniband/acm_prov.h

man_MANS = \
	man/ib_acme.1 \
	man/ibacm.1 \
	man/ibacm.7

EXTRA_DIST = src/acm_util.h prov/acmp/src/libibacmp.map include/acm_mad.h src/libacm.h ibacm.init.in \
	     linux/osd.h linux/dlist.h ibacm.spec.in $(man_MANS) ibacm_hosts.data

install-exec-hook:
	install -D -m 755 ibacm.init $(DESTDIR)$(sysconfdir)/init.d/ibacm;

dist-hook: ibacm.spec
	cp ibacm.spec $(distdir)
