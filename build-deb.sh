#!/bin/bash
#
# Copyright (C) 2012 Roi Dayan <roid@mellanox.com>
#

TARGET=$1
DIR=$(cd `dirname $0`; pwd)
BASE=`cd $DIR ; pwd`
_TOP="$BASE/pkg"


ver=`grep -E "^AC_INIT\(srptools," configure.ac | cut -d, -f 2`
version=`echo $ver`
if [ "$TARGET" = "rel" ]; then
    release="1"
else
    release=`git rev-parse HEAD | cut -c 1-6`
fi

echo "Building version: $version-$release"


cp_src() {
    local dest=$1
    cp -a man $dest
    cp -a autogen.sh $dest
    cp -a configure.ac $dest
    cp -a Makefile.am $dest
    cp -a srptools.spec.in $dest
    cp -a srp_daemon $dest
}

check() {
    local rc=$?
    local msg="$1"
    if (( rc )) ; then
        echo $msg
        exit 1
    fi
}

build_deb() {
    if ! which debuild >/dev/null 2>&1 ; then
        echo "Missing debuild. Please install devscripts package."
        exit 1
    fi
    name=srptools_$version
    TARBALL=$name.orig.tar.gz

    echo "Building under $_TOP/$name"
    mkdir -p $_TOP/$name
    cp_src $_TOP/$name
    tar -czf $_TOP/$TARBALL -C $_TOP $name

    mkdir -p $_TOP/$name/debian
    cp -a debian/* $_TOP/$name/debian
    cd $_TOP/$name
    sed -i -r "s/^srptools \(([0-9.-]+)\) (.*)/srptools \($version-$release\) \2/" debian/changelog
    debuild -uc -us
    check "Failed building deb package."
    cd ../..
    ls -l $_TOP/$name*.deb
}

cd $BASE
build_deb
echo "Done."
