#!/usr/bin/env bash
set -e

LOCALBASE=$(/sbin/sysctl -n user.localbase)
CMAKE=${LOCALBASE}/bin/cmake
NINJA=${LOCALBASE}/bin/ninja
PYTHON=${LOCALBASE}/bin/python3
GCC=${LOCALBASE}/bin/gcc
GXX=${LOCALBASE}/bin/g++

SRCDIR=$(dirname $0)
BUILDDIR=${SRCDIR}/build

mkdir -p ${BUILDDIR}

cd ${BUILDDIR}

${CMAKE} -DIN_PLACE=1 -GNinja -DENABLE_RESOLVE_NEIGH=0 -DIOCTL_MODE=write \
    -DPYTHON_EXECUTABLE=${PYTHON} \
    -DCMAKE_C_COMPILER=${GCC} -DCMAKE_CXX_COMPILER=${GXX} \
    ${EXTRA_CMAKE_FLAGS:-} ..
${NINJA} -k 0
