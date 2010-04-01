INCLUDES = -I$(srcdir)/include -I$(srcdir)/linux

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

bin_PROGRAMS = svc/ib_acm util/ib_acme
svc_ib_acm_SOURCES = src/acm.c
util_ib_acme_SOURCES = src/acme.c linux/acme_linux.c src/libacm.c linux/libacm_linux.c
svc_ib_acm_CFLAGS = $(AM_CFLAGS)
util_ib_acme_CFLAGS = $(AM_CFLAGS)

ib_acmincludedir = $(includedir)/infiniband

ib_acminclude_HEADERS = include/infiniband/acm.h

man_MANS = \
	man/ib_acme.1 \
	man/ib_acm.1 \
	man/ib_acm.7

