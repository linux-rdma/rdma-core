# $Id$

mthcalibdir = $(libdir)/infiniband

mthcalib_LTLIBRARIES = mthca.la

AM_CFLAGS = -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
    mthca_version_script = -Wl,--version-script=$(srcdir)/mthca.map
else
    mthca_version_script =
endif

mthca_la_SOURCES = mthca.c
mthca_la_LDFLAGS = -avoid-version -module \
    $(mthca_version_script)
