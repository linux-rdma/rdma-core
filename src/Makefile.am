# $Id$

INCLUDES = -I$(top_srcdir)/include

lib_LTLIBRARIES = libibverbs.la

AM_CFLAGS = -Wall -D_GNU_SOURCE -DDRIVER_PATH=\"$(libdir)/infiniband\"

if HAVE_LD_VERSION_SCRIPT
    libibverbs_version_script = -Wl,--version-script=$(srcdir)/libibverbs.map
else
    libibverbs_version_script =
endif

libibverbs_la_SOURCES = init.c device.c
libibverbs_la_LDFLAGS = -version-info 1 -export-dynamic \
    $(libibverbs_version_script)
libibverbs_la_DEPENDENCIES = libibverbs.map
