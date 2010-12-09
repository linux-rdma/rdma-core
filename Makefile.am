INCLUDES = -I$(srcdir)/include -I$(srcdir)/linux

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

bin_PROGRAMS = util/ib_acme
sbin_PROGRAMS = svc/ib_acm
svc_ib_acm_SOURCES = src/acm.c
util_ib_acme_SOURCES = src/acme.c linux/acme_linux.c src/libacm.c linux/libacm_linux.c src/parse.c
svc_ib_acm_CFLAGS = $(AM_CFLAGS)
util_ib_acme_CFLAGS = $(AM_CFLAGS)

ibacmincludedir = $(includedir)/infiniband

ibacminclude_HEADERS = include/infiniband/acm.h

man_MANS = \
	man/ib_acme.1 \
	man/ib_acm.1 \
	man/ib_acm.7

EXTRA_DIST = src/acm_mad.h src/libacm.h \
	     linux/osd.h linux/dlist.h ibacm.spec.in $(man_MANS) acm_opts.cfg \
	     acm_addr.cfg

dist-hook: ibacm.spec
	cp ibacm.spec $(distdir)
