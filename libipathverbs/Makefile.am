# Copyright (c) 2007. QLogic Corp. All rights reserved.
# Copyright (c) 2003, 2004, 2005. PathScale, Inc. All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Patent licenses, if any, provided herein do not apply to
# combinations of this program with other software, or any other
# product whatsoever.

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

ipathverbs_version_script = @IPATHVERBS_VERSION_SCRIPT@

IPATHVERBS_SOURCES = src/ipathverbs.c src/verbs.c

if HAVE_IBV_DEVICE_LIBRARY_EXTENSION
    lib_LTLIBRARIES = src/libipathverbs.la
    src_libipathverbs_la_SOURCES = $(IPATHVERBS_SOURCES)
    src_libipathverbs_la_LDFLAGS = -avoid-version -release @IBV_DEVICE_LIBRARY_EXTENSION@ \
        $(ipathverbs_version_script)
    ipathverbsconfdir = $(sysconfdir)/libibverbs.d
    ipathverbsconf_DATA = ipath.driver
else
    ipathverbslibdir = $(libdir)/infiniband
    ipathverbslib_LTLIBRARIES = src/ipathverbs.la
    src_ipathverbs_la_SOURCES = $(IPATHVERBS_SOURCES)
    src_ipathverbs_la_LDFLAGS = -avoid-version -module $(ipathverbs_version_script)
endif
ipathverbsmodprobedir = $(sysconfdir)/modprobe.d
ipathverbsmodprobe_DATA = truescale.conf

EXTRA_DIST = src/ipathverbs.h \
    src/ipath-abi.h \
    src/ipathverbs.map \
    libipathverbs.spec.in \
    ipath.driver \
    truescale-serdes.cmds \
    truescale.conf


sbin_SCRIPTS = truescale-serdes.cmds
if HAS_DRACUT
EXTRA_DIST += dracut_check dracut_install dracut_kmod
dracutdir = $(DESTDIR)$(shell rpm -ql dracut | grep dracut-functions$$ | sed 's/dracut-functions//')modules.d/90qib

install-data-local: dracut_check dracut_install dracut_kmod
	$(INSTALL) -D -m 755 dracut_check $(dracutdir)/check
	$(INSTALL) -D -m 755 dracut_install $(dracutdir)/install
	$(INSTALL) -D -m 755 dracut_kmod $(dracutdir)/installkernel
endif

dist-hook: libipathverbs.spec
	cp libipathverbs.spec $(distdir)
