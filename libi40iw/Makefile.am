lib_LTLIBRARIES = src/libi40iw.la

AM_CPPFLAGS = -I$(srcdir)/src
AM_CFLAGS = -O2 -Wall

if HAVE_LD_VERSION_SCRIPT
    i40iw_version_script = -Wl,--version-script=$(srcdir)/src/i40iw.map
else
    i40iw_version_script =
endif

src_libi40iw_la_SOURCES = src/i40iw_umain.c src/i40iw_uverbs.c src/i40iw_uk.c \
	src/i40iw-abi.h src/i40iw_d.h src/i40iw_osdep.h src/i40iw-register.h \
	src/i40iw-status.h src/i40iw_umain.h src/i40iw_user.h

src_libi40iw_la_LDFLAGS = -avoid-version -module -release @IBV_DEVICE_LIBRARY_EXTENSION@\
    $(i40iw_version_script)

i40iw_confdir = $(sysconfdir)/libibverbs.d
i40iw_conf_DATA = i40iw.driver


EXTRA_DIST = src/i40iw.map libi40iw.spec.in i40iw.driver

dist-hook: libi40iw.spec
	cp libi40iw.spec $(distdir)
