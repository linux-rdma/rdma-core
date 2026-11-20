#!/usr/bin/env bash
set -e

case $(uname -s) in
    Linux)
	if hash cmake3 2>/dev/null; then
	    # CentOS users are encouraged to install cmake3 from EPEL
	    CMAKE=cmake3
	else
	    CMAKE=cmake
	fi
	if hash ninja-build 2>/dev/null; then
	    # Fedora uses this name
	    NINJA=ninja-build
	elif hash ninja 2>/dev/null; then
	    NINJA=ninja
	fi
	PYTHON=python3
	GCC=gcc
	GXX=g++
	MAKE=make
	CMAKE_FLAGS=""
    ;;
    FreeBSD)
	LOCALBASE=$(/sbin/sysctl -n user.localbase)
	CMAKE=${LOCALBASE}/bin/cmake
	NINJA=${LOCALBASE}/bin/ninja
	PYTHON=${LOCALBASE}/bin/python3
	GCC=${LOCALBASE}/bin/gcc
	GXX=${LOCALBASE}/bin/g++
	MAKE=${LOCALBASE}/bin/gmake
	CMAKE_FLAGS="-DENABLE_RESOLVE_NEIGH=0 -DIOCTL_MODE=write"
	;;
    *)
	echo "Port me"
	exit 1
	;;
esac

CMAKE_FLAGS="-DIN_PLACE=1 -DPYTHON_EXECUTABLE=${PYTHON} ${CMAKE_FLAGS}"
CMAKE_FLAGS="-DCMAKE_C_COMPILER=${GCC} -DCMAKE_CXX_COMPILER=${GXX} ${CMAKE_FLAGS}"
SRCDIR=$(dirname $0)
BUILDDIR=${SRCDIR}/build

mkdir -p ${BUILDDIR}

cd ${BUILDDIR}

if [ "x$NINJA" == "x" ]; then
    ${CMAKE} ${CMAKE_FLAGS} ${EXTRA_CMAKE_FLAGS:-} ..
    ${MAKE}
else
    ${CMAKE} -GNinja ${CMAKE_FLAGS} ${EXTRA_CMAKE_FLAGS:-} ..
    ${NINJA} -k 0
fi
