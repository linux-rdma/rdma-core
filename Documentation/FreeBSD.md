# FreeBSD-specific notes

## Base System Requirements

FreeBSD version should be main or stable/15, after the tdestroy(3) and strdupa()/strndupa() additions.

## Packages Required to Build

You need to install the following packages:

 * cmake-core
 * ninja
 * gcc
 * python3
 * pyXXX-cython3
 * pyXXX-docutils
 * bash
 * linuxapi
 * libepoll-shim
 * libudev-devd
 * libdrm
 * pkgconf

## Porting nits

 * All fake constants for (rt)netlink that are added in freebsd-headers/linux point to the usage areas that need eventual porting.
 * There could be missed uses of /proc that needs to be ported.
 * Tests for the compilation environment properties done in CMakeLists.txt are performed before the freebsd-headers get chance to populate build environment.  As such, some tests provide invalid results, e.g. the co-existence of netinet/in.h and linux/in*.h.
