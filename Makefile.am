INCLUDES = -I$(srcdir)/include -I$(srcdir)/linux

lib_LTLIBRARIES = linux/libibacm.la

AM_CFLAGS = -g -Wall -D_GNU_SOURCE -march=i686

linux_libibacm_la_CFLAGS = $(AM_CFLAGS)

if HAVE_LD_VERSION_SCRIPT
    libibacm_version_script = -Wl,--version-script=$(srcdir)/linux/libibacm.map
else
    libibacm_version_script =
endif

linux_libibacm_la_SOURCES = src/libacm.c linux/libacm_linux.c
linux_libibacm_la_LDFLAGS = -version-info 0 -export-dynamic \
			   $(libibacm_version_script)
linux_libibacm_la_DEPENDENCIES =  $(srcdir)/linux/libibacm.map

bin_PROGRAMS = svc/ib_acm util/ib_acme
svc_ib_acm_SOURCES = src/acm.c
util_ib_acme_SOURCES = src/acme.c linux/acme_linux.c
util_ib_acme_LDADD = $(top_builddir)/linux/libibacm.la
svc_ib_acm_CFLAGS = $(AM_CFLAGS)
util_ib_acme_CFLAGS = $(AM_CFLAGS)

libibacmincludedir = $(includedir)/infiniband

libibacminclude_HEADERS = include/infiniband/ib_acm.h include/infiniband/acm.h

man_MANS = \
	man/ib_acm_resolve_name.3 \
	man/ib_acm_resolve_ip.3 \
	man/ib_acm_resolve_path.3 \
	man/ib_acm_query_path.3 \
	man/ib_acm_convert_to_path.3 \
	man/ib_acme.1 \
	man/ib_acm.1 \
	man/ib_acm.7

EXTRA_DIST = linux/libibacm.map libibacm.spec.in $(man_MANS)

dist-hook: libibacm.spec
	cp libibacm.spec $(distdir)
