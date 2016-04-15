# This file is provided under a dual BSD/GPLv2 license.  When using or
# redistributing this file, you may do so under either license.
#
# GPL LICENSE SUMMARY
#
# Copyright(c) 2015 Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# Contact Information:
# Intel Corporation
# www.intel.com
#
# BSD LICENSE
#
# Copyright(c) 2015 Intel Corporation.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Copyright (c) 2007. QLogic Corp. All rights reserved.
# Copyright (c) 2003, 2004, 2005. PathScale, Inc. All rights reserved.

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

hfiverbs_version_script = @HFIVERBS_VERSION_SCRIPT@

HFIVERBS_SOURCES = src/hfiverbs.c src/verbs.c

if HAVE_IBV_DEVICE_LIBRARY_EXTENSION
    lib_LTLIBRARIES = src/libhfi1verbs.la
    src_libhfi1verbs_la_SOURCES = $(HFIVERBS_SOURCES)
    src_libhfi1verbs_la_LDFLAGS = -avoid-version -release @IBV_DEVICE_LIBRARY_EXTENSION@ \
        $(hfiverbs_version_script)
    hfiverbsconfdir = $(sysconfdir)/libibverbs.d
    hfiverbsconf_DATA = hfi1.driver
else
    hfiverbslibdir = $(libdir)/infiniband
    hfiverbslib_LTLIBRARIES = src/hfiverbs.la
    src_hfiverbs_la_SOURCES = $(HFIVERBS_SOURCES)
    src_hfiverbs_la_LDFLAGS = -avoid-version -module $(hfiverbs_version_script)
endif

EXTRA_DIST = src/hfiverbs.h \
    src/hfi-abi.h \
    src/hfiverbs.map \
    config \
    autom4te.cache \
    libhfi1.spec.in \
    hfi1.driver

dist-hook: libhfi1.spec
	cp libhfi1.spec $(distdir)
