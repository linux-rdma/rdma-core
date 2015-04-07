# Copyright (c) 2014. Intel Corporation. All rights reserved.
# Copyright (c) 2007, 2008, 2009. QLogic Corp. All rights reserved.
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
#
# The desired version number comes from the most recent tag starting with "v"
#
NAME = libhfi1verbs
BASEVERSION=0.2
VERSION = $(shell if [ -d .git ] ; then  git describe --tags --abbrev=0 --match='v*' | sed -e 's/^v//' -e 's/-/_/'; else echo "version" ; fi)

# The desired release number comes the git describe following the version which
# is the number of commits since the version tag was planted suffixed by the g<commitid>
RELEASE = $(shell if [ -d .git ] ; then git describe --tags --long --match='v*' | sed -e 's/v[0-9.]*-\([0-9]*\)/\1/' | sed 's/-g.*$$//'; else echo "release" ; fi)

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
		-e 's/@NAME@/'${NAME}'/g' ${NAME}.spec.in > ${NAME}.spec
	if [ -d .git ]; then \
		echo '%changelog' >> ${NAME}.spec; \
		git log --no-merges v$(BASEVERSION)..HEAD --format="* %cd <%ae>%n- %s%n" \
		| sed 's/-[0-9][0-9][0-9][0-9] //' \
		| sed 's/ [0-9][0-9]:[0-9][0-9]:[0-9][0-9]//' \
		>> ${NAME}.spec ; \
	fi

dist: distclean ${NAME}.spec
	rm -rf /tmp/${NAME}-$(VERSION)
	mkdir -p /tmp/${NAME}-$(VERSION)
	cp -r . /tmp/${NAME}-$(VERSION)
	tar $(EXCLUDES) -C /tmp -zcvf $(PWD)/${NAME}-$(VERSION).tar.gz ${NAME}-$(VERSION)
	rm -rf /tmp/${NAME}-$(VERSION)

