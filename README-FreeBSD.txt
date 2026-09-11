The port just compiles.

FreeBSD version should be main or stable/15, after the tdestroy(3) and
strdupa()/strndupa() additions.

You need to install the following packages:
cmake-core
ninja
gcc
python3
pyXXX-cython3
pyXXX-docutils
bash
libepoll-shim
libudev-devd
libdrm
pkgconf

1. All fake constants for (rt)netlink that are added in
   freebsd-headers/linux point to the usage areas that need porting.
2. sysfs accesses must be replaced by sysctl.
   Similarly, there should be use of /proc that needs to be ported.
3. I have no idea if the FreeBSD verbs/drivers ABI is compatible with
   the Linux provided by kernel-headers/*.
4. Tests for the compilation environment properties done in CMakeLists.txt
   are performed before the freebsd-headers get chance to populate build
   environment.  As such, some tests provide invalid results, e.g.
   the co-existence of netinet/in.h and linux/in*.h.
