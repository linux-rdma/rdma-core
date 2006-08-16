# $Id$

SUBDIRS = srp_daemon

sbin_PROGRAMS = src/ibsrpdm

src_ibsrpdm_CFLAGS = -Wall
src_ibsrpdm_SOURCES = src/srp-dm.c

EXTRA_DIST = \
    src/srp-dm.h \
    src/ib_user_mad.h \
    srptools.spec.in

dist-hook: srptools.spec
	cp srptools.spec $(distdir)
