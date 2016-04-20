# Copyright(c) 2015 Intel Corporation.
#
# This file is provided under a dual BSD/GPLv2 license.  When using or
# redistributing this file, you may do so under either license.
#
# GPL LICENSE SUMMARY
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
# Copyright (c) 2014-2016. Intel Corporation. All rights reserved.
# Copyright (c) 2007, 2008, 2009. QLogic Corp. All rights reserved.
# Copyright (c) 2003, 2004, 2005. PathScale, Inc. All rights reserved.
#
# The desired version number comes from the most recent tag starting with "v"
#
NAME = libhfi1
BASEVERSION=0.2
GEN_IBVERBS=1.0-0.5.rc7
FED_IBVERBS=1.2.0
VERSION = $(shell if [ -e .git ] ; then  git describe --tags --abbrev=0 --match='v*' | sed -e 's/^v//' -e 's/-/_/'; else echo "version" ; fi)

# The desired release number comes the git describe following the version which
# is the number of commits since the version tag was planted suffixed by the g<commitid>
RELEASE = $(shell if [ -e .git ] ; then git describe --tags --long --match='v*' | sed -e 's/v[0-9.]*-\([0-9]*\)/\1/' | sed 's/-g.*$$//'; else echo "release" ; fi)

EXCLUDES = --exclude-vcs --exclude-backups --exclude='*.patch' --exclude='*.swp' --exclude='series' --exclude='*.orig' --exclude=makefile --exclude=${NAME}.spec.in

distclean:
	if [ -f Makefile ] ; then \
		${MAKE} -f Makefile clean ; \
	fi
	rm -f ${NAME}.spec
	rm -f *.tar.gz *.tgz

${NAME}.spec: ${NAME}.spec.in
	sed \
		-e 's/@VERSION@/'${VERSION}'/g' \
		-e 's/@RELEASE@/'${RELEASE}'/g' \
		-e 's/@IBVERBS@/'${GEN_IBVERBS}'/g' \
		-e 's/@NAME@/'${NAME}'/g' ${NAME}.spec.in > ${NAME}.spec
	if [ -e .git ]; then \
		echo '%changelog' >> ${NAME}.spec; \
		cat fedora_changelog.txt >> ${NAME}.spec ; \
	fi

${NAME}.spec.fed: ${NAME}.spec.in
	sed \
		-e 's/@VERSION@/'${VERSION}'/g' \
		-e 's/@RELEASE@/'${RELEASE}'/g' \
		-e 's/@IBVERBS@/'${FED_IBVERBS}'/g' \
		-e 's/@NAME@/'${NAME}'/g' ${NAME}.spec.in > ${NAME}.spec
	if [ -e .git ]; then \
		echo '%changelog' >> ${NAME}.spec; \
		cat fedora_changelog.txt \
		>> ${NAME}.spec ; \
	fi

gen_dist:
	rm -rf /tmp/${NAME}-$(VERSION)
	mkdir -p /tmp/${NAME}-$(VERSION)
	cp -r . /tmp/${NAME}-$(VERSION)
	tar $(EXCLUDES) -C /tmp -zcvf $(PWD)/${NAME}-$(VERSION).tar.gz ${NAME}-$(VERSION)
	rm -rf /tmp/${NAME}-$(VERSION)

dist: distclean ${NAME}.spec gen_dist


fedora_dist: distclean ${NAME}.spec.fed gen_dist
