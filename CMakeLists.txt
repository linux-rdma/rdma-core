# COPYRIGHT (c) 2016 Obsidian Research Corporation. See COPYING file
# Run cmake as:
#  mkdir build
#  cmake -GNinja ..
#  ninja
#
# Common options passed to cmake are:
#  -DIN_PLACE=1
#      Configure the build to be run from the build directory, this results in something
#      that is not installable.
#  -DCMAKE_EXPORT_COMPILE_COMMANDS=1
#      Write a compile_commands.json file for clang tooling
#  -DCMAKE_BUILD_TYPE=RelWithDebInfo
#      Change the optimization level, Debug disables optimization,
#      Release is for packagers
#  -DENABLE_VALGRIND=0 (default enabled)
#      Disable valgrind notations, this has a tiny positive performance impact
#  -DENABLE_RESOLVE_NEIGH=0 (default enabled)
#      Do not link to libnl and do not resolve neighbours internally for Ethernet,
#      and do not build iwpmd.
#  -DENABLE_STATIC=1 (default disabled)
#      Produce static libraries along with the usual shared libraries.
#  -DVERBS_PROVIDER_DIR='' (default /usr/lib.../libibverbs)
#      Use the historical search path for providers, in the standard system library.
#  -DNO_COMPAT_SYMS=1 (default disabled)
#      Do not generate backwards compatibility symbols in the shared
#      libraries. This may is necessary if using a dynmic linker that does
#      not support symbol versions, such as uclibc.
#  -DIOCTL_MODE=write (default both)
#      Disable new kABI ioctl() support and support only the legacy write
#      path. May also be 'ioctl' to disable fallback to write.
#  -DIBACM_SERVER_MODE_DEFAULT (default unix)
#      Selects how clients can connect to this server:
#      open) Allow incoming connections from any TCP client (internal or external).
#      loop) Limit incoming connections for server_port to 127.0.0.1.
#      unix) Use unix-domain sockets, hence limits service to the same machine.
#  -DIBACM_ACME_PLUS_KERNEL_ONLY_DEFAULT (default 0)
#      If non-zero, limit incoming requests to kernel or the ib_acme utility
#      (i.e. do not serve librdmacm requests)
#  -DPYTHON_EXECUTABLE
#      Override automatic detection of python to use a certain
#      exectuable. This can be used to force the build to use python2 on a
#      system that has python3 installed. Otherwise the build automatically
#      prefers python3 if available.
#   -DNO_PYVERBS=1 (default, build pyverbs)
#      Invoke cython to build pyverbs. Usually you will run with this option
#      set
#   -DENABLE_IBDIAGS_COMPAT=True (default False)
#      Include obsolete scripts. These scripts are replaced by C programs with
#      a different interface now.
#   -DNO_MAN_PAGES=1 (default 0, build/install the man pages)
#      Disable man pages. Allows rdma-core to be built and installed
#      (without man pages) when neither pandoc/rst2man nor the pandoc-prebuilt
#      directory are available.

if (${CMAKE_VERSION} VERSION_LESS "3.18.1")
	# Centos 6 support
	cmake_minimum_required(VERSION 2.8.11 FATAL_ERROR)
else()
	cmake_minimum_required(VERSION 3.18.1 FATAL_ERROR)
endif()
project(rdma-core C)

# CMake likes to use -rdynamic too much, they fixed it in 3.4.
if(POLICY CMP0065)
  cmake_policy(SET CMP0065 NEW)
else()
  # .. but we really do want to opt out.
  string(REPLACE "-rdynamic" "" CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "${CMAKE_SHARED_LIBRARY_LINK_C_FLAGS}")
endif()

# Make RDMA_CHECK_C_LINKER_FLAG work better
if(POLICY CMP0056)
  cmake_policy(SET CMP0056 NEW)
endif()

set(PACKAGE_NAME "RDMA")

# See Documentation/versioning.md
set(PACKAGE_VERSION "39.0")
# When this is changed the values in these files need changing too:
#   debian/control
#   debian/libibverbs1.symbols
set(IBVERBS_PABI_VERSION "34")
set(IBVERBS_PROVIDER_SUFFIX "-rdmav${IBVERBS_PABI_VERSION}.so")

#-------------------------
# Basic standard paths

# Override the CMAKE_INSTALL_ dirs to be under the build/ directory
if (IN_PLACE)
  set(CMAKE_INSTALL_SYSCONFDIR "${CMAKE_BINARY_DIR}/etc")
  set(CMAKE_INSTALL_BINDIR "${CMAKE_BINARY_DIR}/bin")
  set(CMAKE_INSTALL_SBINDIR "${CMAKE_BINARY_DIR}/bin")
  set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}")
  set(CMAKE_INSTALL_LIBDIR "lib")
  set(CMAKE_INSTALL_INCLUDEDIR "include")
endif()

include(GNUInstallDirs)
# C include root
set(BUILD_INCLUDE ${CMAKE_BINARY_DIR}/include)
# Executables
set(BUILD_BIN ${CMAKE_BINARY_DIR}/bin)
# Libraries
set(BUILD_LIB ${CMAKE_BINARY_DIR}/lib)
# Static library pre-processing
set(BUILD_STATIC_LIB ${CMAKE_BINARY_DIR}/lib/statics)
# Used for IN_PLACE configuration
set(BUILD_ETC ${CMAKE_BINARY_DIR}/etc)
set(BUILD_PYTHON ${CMAKE_BINARY_DIR}/python)

set(IBDIAG_CONFIG_PATH "${CMAKE_INSTALL_FULL_SYSCONFDIR}/infiniband-diags")
set(IBDIAG_NODENAME_MAP_PATH "${CMAKE_INSTALL_FULL_SYSCONFDIR}/rdma/ib-node-name-map")

set(CMAKE_INSTALL_INITDDIR "${CMAKE_INSTALL_SYSCONFDIR}/init.d"
  CACHE PATH "Location for init.d files")
set(CMAKE_INSTALL_SYSTEMD_SERVICEDIR "${CMAKE_INSTALL_PREFIX}/lib/systemd/system"
  CACHE PATH "Location for systemd service files")
set(CMAKE_INSTALL_SYSTEMD_BINDIR "/lib/systemd"
  CACHE PATH "Location for systemd extra binaries")

set(ACM_PROVIDER_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/ibacm"
  CACHE PATH "Location for ibacm provider plugin shared library files.")
# Location to find the provider plugin shared library files
set(VERBS_PROVIDER_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/libibverbs"
  CACHE PATH "Location for provider plugin shared library files. If set to empty the system search path is used.")

# Allow the 'run' dir to be configurable, this historically has been /var/run, but
# some systems now use /run/
set(CMAKE_INSTALL_RUNDIR "var/run"
  CACHE PATH "Location for runtime information, typically /var/run, or /run")
if(NOT IS_ABSOLUTE ${CMAKE_INSTALL_RUNDIR})
  set(CMAKE_INSTALL_FULL_RUNDIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_RUNDIR}")
else()
  set(CMAKE_INSTALL_FULL_RUNDIR "${CMAKE_INSTALL_RUNDIR}")
endif()

# Allow the udev rules.d dir to be configurable, this has historically been
# /lib/udev/rules.d/, but some systems now prefix /usr/
set(CMAKE_INSTALL_UDEV_RULESDIR "lib/udev/rules.d"
  CACHE PATH "Location for system udev rules, typically /lib/udev/rules.d or /usr/lib/udev/rules.d")
if(NOT IS_ABSOLUTE ${CMAKE_INSTALL_UDEV_RULESDIR})
  set(CMAKE_INSTALL_FULL_UDEV_RULESDIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_UDEV_RULESDIR}")
else()
  set(CMAKE_INSTALL_FULL_UDEV_RULESDIR "${CMAKE_INSTALL_UDEV_RULESDIR}")
endif()

# Allow the perl library dir to be configurable
set(CMAKE_INSTALL_PERLDIR "share/perl5"
  CACHE PATH "Location for system perl library, typically /usr/share/perl5")
if(NOT IS_ABSOLUTE ${CMAKE_INSTALL_PERLDIR})
  set(CMAKE_INSTALL_FULL_PERLDIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_PERLDIR}")
else()
  set(CMAKE_INSTALL_FULL_PERLDIR "${CMAKE_INSTALL_PERLDIR}")
endif()

# Location to place provider .driver files
if (IN_PLACE)
  set(CONFIG_DIR "${BUILD_ETC}/libibverbs.d")
  set(VERBS_PROVIDER_DIR "${BUILD_LIB}")
  set(ACM_PROVIDER_DIR "${BUILD_LIB}/ibacm")
else()
  set(CONFIG_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/libibverbs.d")
endif()

set(DISTRO_FLAVOUR "None" CACHE
  STRING "Flavour of distribution to install for. This primarily impacts the init.d scripts installed.")

#-------------------------
# Load CMake components
set(BUILDLIB "${CMAKE_SOURCE_DIR}/buildlib")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${BUILDLIB}")

include(CMakeParseArguments)
include(CheckCCompilerFlag)
include(CheckIncludeFile)
include(CheckTypeSize)
include(RDMA_EnableCStd)
include(RDMA_Sparse)
include(RDMA_BuildType)
include(RDMA_DoFixup)
include(publish_headers)
include(rdma_functions)
include(pyverbs_functions)
if (NO_MAN_PAGES)
  # define empty stub functions to omit man page processing
  function(rdma_man_pages)
  endfunction()
  function(rdma_alias_man_pages)
  endfunction()
else()
  include(rdma_man)
endif()

if (NOT DEFINED ENABLE_STATIC)
  set(ENABLE_STATIC "OFF" CACHE BOOL "Produce static linking libraries as well as shared libraries.")
endif()

#-------------------------
# Setup the basic C compiler
RDMA_BuildType()
include_directories(${BUILD_INCLUDE})

# Look for Python. We prefer some variant of python 3 if the system has it.
FIND_PACKAGE(PythonInterp 3 QUIET)
if (PythonInterp_FOUND)
  # pyverbs can only use python3:
  if (NO_PYVERBS)
    set(CYTHON_EXECUTABLE "")
  else()
    FIND_PACKAGE(cython)
  endif()
else()
  # But we still must have python (be it 2) for the build process:
  FIND_PACKAGE(PythonInterp REQUIRED)
  set(CYTHON_EXECUTABLE "")
endif()

RDMA_CheckSparse()

# Require GNU99 mode
RDMA_EnableCStd()

# Extra warnings. Turn on -Wextra to keep aware of interesting developments from gcc,
# but turn off some that are not terribly useful for this source.
# FIXME: I wonder how many of the signed compares are bugs?
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WARNINGS
  "-Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wno-stringop-overread")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WMISSING_PROTOTYPES "-Wmissing-prototypes")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WMISSING_DECLARATIONS "-Wmissing-declarations")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WWRITE_STRINGS "-Wwrite-strings")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WFORMAT_2 "-Wformat=2")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WCAST_FUNCTION "-Wcast-function-type")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WFORMAT_NONLITERAL "-Wformat-nonliteral")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WDATE_TIME "-Wdate-time")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WNESTED_EXTERNS "-Wnested-externs")

# At some point after 4.4 gcc fixed shadow to ignore function vs variable
# conflicts
RDMA_Check_C_Compiles(HAVE_C_WORKING_SHADOW "
 #include <unistd.h>
 int main(int argc,const char *argv[]) { int access = 1; return access; }"
  "-Wshadow")
if (HAVE_C_WORKING_SHADOW)
  RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WORKING_SHADOW "-Wshadow")
endif()

# At some point around 5.4 gcc fixed missing-field-initializers to ignore this
# common idiom we use extensively. Since this is a useful warning for
# developers try and leave it on if the compiler supports it.
RDMA_Check_C_Compiles(HAVE_C_WORKING_MISSING_FIELD_INITIALIZERS "
 struct foo { int a; int b; };
 int main(int argc,const char *argv[]) { struct foo tmp = {}; return tmp.a; }"
)
if (NOT HAVE_C_WORKING_MISSING_FIELD_INITIALIZERS)
  RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WNO_MISSING_FIELD_INITIALIZERS "-Wno-missing-field-initializers")
endif()

# Check that the compiler supports -fno-strict-aliasing.
# The use of this flag in the source is discouraged
set(NO_STRICT_ALIASING_FLAGS "")
RDMA_AddOptCFlag(NO_STRICT_ALIASING_FLAGS HAVE_NO_STRICT_ALIASING
  "-fno-strict-aliasing")

# pyverbs has a problem with var-tracking warnings, turn it off if we can.
set(NO_VAR_TRACKING_FLAGS "")
RDMA_AddOptCFlag(NO_VAR_TRACKING_FLAGS HAVE_NO_VAR_TRACKING_ASSIGNMENTS
  "-fno-var-tracking-assignments")

RDMA_Check_C_Compiles(HAVE_FUNC_ATTRIBUTE_IFUNC "
 #include <unistd.h>

 void entry(void);

 static void do_entry(void) {}
 void entry(void) __attribute__((ifunc(\"resolve_entry\")));
 typedef void (*fn_t)(void);
 static fn_t resolve_entry(void) {return &do_entry;}

 int main(int argc,const char *argv[]) { entry(); }"
)

RDMA_Check_C_Compiles(HAVE_FUNC_ATTRIBUTE_SYMVER "
 #include <unistd.h>

 void _sym(void);
 __attribute__((__symver__(\"sym@TEST_1.1\"))) void _sym(void) {}

 int main(int argc,const char *argv[]) { _sym(); }"
)

# The code does not do the racy fcntl if the various CLOEXEC's are not
# supported so it really doesn't work right if this isn't available. Thus hard
# require it.
CHECK_C_SOURCE_COMPILES("
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <sys/socket.h>
 #include <fcntl.h>
 int main(int argc,const char *argv[]) {
    open(\".\",O_RDONLY | O_CLOEXEC);
    socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    return 0;
 }" HAS_CLOEXEC)

if (NOT HAS_CLOEXEC)
# At least uclibc wrongly hides this POSIX constant behind _GNU_SOURCE
CHECK_C_SOURCE_COMPILES("
 #define _GNU_SOURCE
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <sys/socket.h>
 #include <fcntl.h>
 int main(int argc,const char *argv[]) {
    open(\".\",O_RDONLY | O_CLOEXEC);
    socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    return 0;
 }" HAS_CLOEXEC_GNU_SOURCE)
  if (HAS_CLOEXEC_GNU_SOURCE)
    set(HAS_CLOEXEC 1)
    add_definitions("-D_GNU_SOURCE=")
  endif()
endif()

if (NOT HAS_CLOEXEC)
  message(FATAL_ERROR "O_CLOEXEC/SOCK_CLOEXEC/fopen(..,\"e\") support is required but not found")
endif()

# always_inline is supported
RDMA_Check_C_Compiles(HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE "
 int foo(void);
 inline __attribute__((always_inline)) int foo(void) {return 0;}
 int main(int argc,const char *argv[]) { return foo(); }"
)

# Linux __u64 is an unsigned long long
RDMA_Check_C_Compiles(HAVE_LONG_LONG_U64 "
#include <linux/types.h>
 int main(int argc,const char *argv[]) { __u64 tmp = 0; unsigned long long *tmp2 = &tmp; return *tmp2; }"
)

if (NOT HAVE_LONG_LONG_U64)
  # Modern Linux has switched to use ull in all cases, but to avoid disturbing
  # userspace some platforms continued to use unsigned long by default. This
  # define will cause kernel headers to consistently use unsigned long long
  add_definitions("-D__SANE_USERSPACE_TYPES__")
endif()

# glibc and kernel uapi headers can co-exist
CHECK_C_SOURCE_COMPILES("
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <linux/in.h>
 #include <linux/in6.h>
 int main(int argc,const char *argv[]) { return 0; }"
  HAVE_GLIBC_UAPI_COMPAT)
RDMA_DoFixup("${HAVE_GLIBC_UAPI_COMPAT}" "linux/in.h")
RDMA_DoFixup("${HAVE_GLIBC_UAPI_COMPAT}" "linux/in6.h")

# The compiler has working -fstrict-aliasing support, old gcc's do not. If
# broken then globally disable strict aliasing.
RDMA_Check_Aliasing(HAVE_WORKING_STRICT_ALIASING)
if (NOT HAVE_WORKING_STRICT_ALIASING)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NO_STRICT_ALIASING_FLAGS}")
endif()

# Check if off_t is 64 bits, eg large file support is enabled
CHECK_C_SOURCE_COMPILES("
#include <sys/types.h>
 #define BUILD_ASSERT_OR_ZERO(cond) (sizeof(char [1 - 2*!(cond)]) - 1)
 int main(int argc,const char *argv[]) { return BUILD_ASSERT_OR_ZERO(sizeof(off_t) >= 8); }"
  HAVE_LARGE_FILES)

if (NOT HAVE_LARGE_FILES)
  CHECK_C_SOURCE_COMPILES("
#define _FILE_OFFSET_BITS 64
#include <sys/types.h>
 #define BUILD_ASSERT_OR_ZERO(cond) (sizeof(char [1 - 2*!(cond)]) - 1)
 int main(int argc,const char *argv[]) { return BUILD_ASSERT_OR_ZERO(sizeof(off_t) >= 8); }"
    HAVE_LARGE_FILES2)
  if (NOT HAVE_LARGE_FILES2)
    message(FATAL_ERROR "Could not enable large file support")
  endif()
  add_definitions("-D_FILE_OFFSET_BITS=64")
endif()

# Provide a shim if C11 stdatomic.h is not supported.
if (NOT HAVE_SPARSE)
  CHECK_INCLUDE_FILE("stdatomic.h" HAVE_STDATOMIC)
  RDMA_DoFixup("${HAVE_STDATOMIC}" "stdatomic.h")
endif()

RDMA_Check_SSE(HAVE_TARGET_SSE)

# Enable development support features
# Prune unneeded shared libraries during linking
RDMA_AddOptLDFlag(CMAKE_EXE_LINKER_FLAGS SUPPORTS_AS_NEEDED "-Wl,--as-needed")
RDMA_AddOptLDFlag(CMAKE_SHARED_LINKER_FLAGS SUPPORTS_AS_NEEDED "-Wl,--as-needed")
RDMA_AddOptLDFlag(CMAKE_MODULE_LINKER_FLAGS SUPPORTS_AS_NEEDED "-Wl,--as-needed")

# Ensure all shared ELFs have fully described linking
RDMA_AddOptLDFlag(CMAKE_EXE_LINKER_FLAGS SUPPORTS_NO_UNDEFINED "-Wl,--no-undefined")
RDMA_AddOptLDFlag(CMAKE_SHARED_LINKER_FLAGS SUPPORTS_NO_UNDEFINED "-Wl,--no-undefined")

# Enable gold linker - gold has different linking checks
#RDMA_AddOptLDFlag(CMAKE_EXE_LINKER_FLAGS SUPPORTS_NO_UNDEFINED "-fuse-ld=gold")
#RDMA_AddOptLDFlag(CMAKE_SHARED_LINKER_FLAGS SUPPORTS_NO_UNDEFINED "-fuse-ld=gold")
#RDMA_AddOptLDFlag(CMAKE_MODULE_LINKER_FLAGS SUPPORTS_NO_UNDEFINED "-fuse-ld=gold")

# Verify that GNU --version-script and asm(".symver") works
find_package(LDSymVer REQUIRED)
if (NO_COMPAT_SYMS)
  set(HAVE_LIMITED_SYMBOL_VERSIONS 1)
else()
  set(HAVE_FULL_SYMBOL_VERSIONS 1)
endif()

# A cython & python-devel installation that matches our selected interpreter.

if (CYTHON_EXECUTABLE)
 # cmake has really bad logic here, if PythonIterp has been run it tries to
 # find a matching -devel installation but will happily return a non-matching
 # one too. We need them both to match exactly to guarantee cython does the
 # right thing.
  FIND_PACKAGE(PythonLibs ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}
    EXACT REQUIRED)

 # Get a default installation path
  execute_process(COMMAND "${PYTHON_EXECUTABLE}" -c
    "import sysconfig; print(sysconfig.get_path(\"platlib\"))"
  OUTPUT_VARIABLE py_path)
  string(STRIP ${py_path} py_path)
  set(CMAKE_INSTALL_PYTHON_ARCH_LIB "${py_path}"
  CACHE PATH "Location for architecture specific python libraries")

 # See PEP3149
  execute_process(COMMAND "${PYTHON_EXECUTABLE}" -c
    "import sysconfig; x = sysconfig.get_config_var(\"EXT_SUFFIX\"); print(x if x else '.so')"
    OUTPUT_VARIABLE py_path)
  string(STRIP ${py_path} CMAKE_PYTHON_SO_SUFFIX)
endif()

set(NO_MAN_PAGES "OFF" CACHE BOOL "Disable build/install of man pages")
if (NOT NO_MAN_PAGES)
  # Look for pandoc and rst2man for making manual pages
  FIND_PACKAGE(pandoc)
  FIND_PACKAGE(rst2man)
endif ()

#-------------------------
# Find libraries
# pthread
FIND_PACKAGE (Threads REQUIRED)

FIND_PACKAGE(PkgConfig REQUIRED)

# libnl
if (NOT DEFINED ENABLE_RESOLVE_NEIGH)
  set(ENABLE_RESOLVE_NEIGH "ON" CACHE BOOL "Enable internal resolution of neighbours for Etherent")
endif()
if (ENABLE_RESOLVE_NEIGH)
  # FIXME use of pkgconfig is discouraged
  pkg_check_modules(NL libnl-3.0 libnl-route-3.0 REQUIRED)
  include_directories(${NL_INCLUDE_DIRS})
  link_directories(${NL_LIBRARY_DIRS})
  set(NL_KIND 3)
else()
  set(NL_KIND 0)
  set(NL_LIBRARIES "")
  RDMA_DoFixup(0 "netlink/attr.h")
  RDMA_DoFixup(0 "netlink/msg.h")
  RDMA_DoFixup(0 "netlink/netlink.h")
  RDMA_DoFixup(0 "netlink/object-api.h")
  RDMA_DoFixup(0 "netlink/route/link.h")
  RDMA_DoFixup(0 "netlink/route/link/vlan.h")
  RDMA_DoFixup(0 "netlink/route/neighbour.h")
  RDMA_DoFixup(0 "netlink/route/route.h")
  RDMA_DoFixup(0 "netlink/route/rtnl.h")
endif()

# Older stuff blows up if these headers are included together
if (NOT NL_KIND EQUAL 0)
  set(SAFE_CMAKE_REQUIRED_INCLUDES "${CMAKE_REQUIRED_INCLUDES}")
  set(CMAKE_REQUIRED_INCLUDES "${NL_INCLUDE_DIRS}")
  CHECK_C_SOURCE_COMPILES("
#include <netlink/route/link.h>
#include <net/if.h>
 int main(int argc,const char *argv[]) {return 0;}"
    HAVE_WORKING_IF_H)
  set(CMAKE_REQUIRED_INCLUDES "${SAFE_CMAKE_REQUIRED_INCLUDES}")
endif()

# udev
find_package(UDev)
include_directories(${UDEV_INCLUDE_DIRS})

# Statically determine sizeof(long), this is largely unnecessary, no new code
# should rely on this.
check_type_size("long" SIZEOF_LONG BUILTIN_TYPES_ONLY LANGUAGE C)

# Determine if this arch supports cache coherent DMA. This isn't really an
# arch specific property, but for our purposes arches that do not support it
# also do not define wmb/etc which breaks our compile.
CHECK_C_SOURCE_COMPILES("
#include \"${CMAKE_CURRENT_SOURCE_DIR}/util/udma_barrier.h\"
 int main(int argc,const char *argv[]) {return 0;}"
  HAVE_COHERENT_DMA)

find_package(Systemd)
include_directories(${SYSTEMD_INCLUDE_DIRS})
RDMA_DoFixup("${SYSTEMD_FOUND}" "systemd/sd-daemon.h")

# drm headers

# Check if the headers have been installed by kernel-headers
find_path(DRM_INCLUDE_DIRS "drm.h" PATH_SUFFIXES "drm")

# Alternatively the headers could have been installed by libdrm
if (NOT DRM_INCLUDE_DIRS)
  pkg_check_modules(DRM libdrm)
endif()

if (DRM_INCLUDE_DIRS)
  if (EXISTS ${DRM_INCLUDE_DIRS}/i915_drm.h AND EXISTS ${DRM_INCLUDE_DIRS}/amdgpu_drm.h)
    include_directories(${DRM_INCLUDE_DIRS})
  else()
    unset(DRM_INCLUDE_DIRS CACHE)
  endif()
endif()

#-------------------------
# Apply fixups

# We prefer to build with valgrind memcheck.h present, but if not, or the user
# requested valgrind disabled, then replace it with our dummy stub.
if (NOT DEFINED ENABLE_VALGRIND)
  set(ENABLE_VALGRIND "ON" CACHE BOOL "Enable use of valgrind annotations")
endif()
if (ENABLE_VALGRIND)
  CHECK_INCLUDE_FILE("valgrind/memcheck.h" HAVE_VALGRIND_MEMCHECK)
  CHECK_INCLUDE_FILE("valgrind/drd.h" HAVE_VALGRIND_DRD)
else()
  set(HAVE_VALGRIND_MEMCHECK 0)
  set(HAVE_VALGRIND_DRD 0)
endif()
RDMA_DoFixup("${HAVE_VALGRIND_MEMCHECK}" "valgrind/memcheck.h")
RDMA_DoFixup("${HAVE_VALGRIND_DRD}" "valgrind/drd.h")

# Older glibc does not include librt
CHECK_C_SOURCE_COMPILES("
#include <time.h>
int main(int argc,const char *argv[]) {
   clock_gettime(CLOCK_MONOTONIC,0);
   clock_nanosleep(CLOCK_MONOTONIC,0,0,0);
   return 0;
};" LIBC_HAS_LIBRT)
if (NOT LIBC_HAS_LIBRT)
  set(RT_LIBRARIES "rt")
endif()

# Check for static_assert
CHECK_C_SOURCE_COMPILES("
#include <assert.h>
static_assert(1, \"failed\");
int main(int argc,const char *argv[]) {
   static_assert(1, \"failed\");
   return 0;
};" HAVE_STATIC_ASSERT)
RDMA_DoFixup("${HAVE_STATIC_ASSERT}" "assert.h")

#-------------------------
# Final warning flags

# Old version of cmake used 'main(){..}' as their test program which breaks with -Werror.
# So set this flag last.
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WSTRICT_PROTOTYPES "-Wstrict-prototypes")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WOLD_STYLE_DEFINITION "-Wold-style-definition")

if (ENABLE_WERROR)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
  message(STATUS "Enabled -Werror")
endif()

# Old versions of libnl have a duplicated rtnl_route_put, disbale the warning on those
# systems
if (NOT NL_KIND EQUAL 0)
  set(SAFE_CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_INCLUDES "${NL_INCLUDE_DIRS}")
  RDMA_Check_C_Compiles(HAVE_C_WREDUNDANT_DECLS "
 #include <netlink/route/route.h>
 int main(int argc,const char *argv[]) { return 0; }"
  "-Wredundant-decls")
  set(CMAKE_REQUIRED_INCLUDES "${SAFE_CMAKE_REQUIRED_INCLUDES}")
endif()
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WREDUNDANT_DECLS "-Wredundant-decls")

# Support of getrandom() was added to glibc in version 2.25
CHECK_C_SOURCE_COMPILES("
 #include <sys/random.h>
 int main(int argc,const char *argv[]) {char buf[64]; return getrandom(buf, 64, GRND_NONBLOCK);}"
 HAVE_GLIBC_GETRANDOM)
RDMA_DoFixup("${HAVE_GLIBC_GETRANDOM}" "sys/random.h")

# glibc 2.33 and newer stopped to properly declare __fxstat in sys/stat.h
RDMA_Check_C_Compiles(HAVE_GLIBC_FXSTAT "
 #include <sys/stat.h>
 int main(int argc,const char *argv[]) {
 struct stat stat = {};  __fxstat(0, 0, &stat);  return 0;}")
RDMA_DoFixup("${HAVE_GLIBC_FXSTAT}" "sys/stat.h")

#-------------------------
# Build Prep
# Write out a git ignore file to the build directory if it isn't the source
# directory. For developer convenience
if (NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
  file(WRITE ${CMAKE_BINARY_DIR}/.gitignore "*")
endif()

if ("${IOCTL_MODE}" STREQUAL "both")
  set(IOCTL_MODE_NUM 3)
elseif ("${IOCTL_MODE}" STREQUAL "write")
  set(IOCTL_MODE_NUM 2)
elseif ("${IOCTL_MODE}" STREQUAL "ioctl")
  set(IOCTL_MODE_NUM 1)
elseif ("${IOCTL_MODE}" STREQUAL "")
  set(IOCTL_MODE_NUM 3)
else()
  message(FATAL_ERROR "-DIOCTL_MODE=${IOCTL_MODE} is not a valid choice")
endif()

# Configuration defaults

if ("${IBACM_SERVER_MODE_DEFAULT}" STREQUAL "open")
  set(IBACM_SERVER_MODE_DEFAULT "IBACM_SERVER_MODE_OPEN")
elseif ("${IBACM_SERVER_MODE_DEFAULT}" STREQUAL "loop")
  set(IBACM_SERVER_MODE_DEFAULT "IBACM_SERVER_MODE_LOOP")
else()
  set(IBACM_SERVER_MODE_DEFAULT "IBACM_SERVER_MODE_UNIX")
endif()

if (IBACM_ACME_PLUS_KERNEL_ONLY_DEFAULT)
  set(IBACM_ACME_PLUS_KERNEL_ONLY_DEFAULT 1)
else()
  set(IBACM_ACME_PLUS_KERNEL_ONLY_DEFAULT 0)
endif()

configure_file("${BUILDLIB}/config.h.in" "${BUILD_INCLUDE}/config.h" ESCAPE_QUOTES @ONLY)

#-------------------------
# Sub-directories
add_subdirectory(ccan)
add_subdirectory(util)
add_subdirectory(Documentation)
add_subdirectory(kernel-boot)
add_subdirectory(kernel-headers)
# Libraries
add_subdirectory(libibumad)
add_subdirectory(libibumad/man)
add_subdirectory(libibverbs)
add_subdirectory(libibverbs/man)
add_subdirectory(librdmacm)
add_subdirectory(librdmacm/man)

# Providers
if (HAVE_COHERENT_DMA)
add_subdirectory(providers/bnxt_re)
add_subdirectory(providers/cxgb4) # NO SPARSE
add_subdirectory(providers/efa)
add_subdirectory(providers/efa/man)
add_subdirectory(providers/hns)
add_subdirectory(providers/irdma)
add_subdirectory(providers/mlx4)
add_subdirectory(providers/mlx4/man)
add_subdirectory(providers/mlx5)
add_subdirectory(providers/mlx5/man)
add_subdirectory(providers/mthca)
add_subdirectory(providers/ocrdma)
add_subdirectory(providers/qedr)
add_subdirectory(providers/vmw_pvrdma)
endif()

add_subdirectory(providers/hfi1verbs)
add_subdirectory(providers/ipathverbs)
add_subdirectory(providers/rxe)
add_subdirectory(providers/rxe/man)
add_subdirectory(providers/siw)

add_subdirectory(libibmad)
add_subdirectory(libibnetdisc)
add_subdirectory(libibnetdisc/man)
add_subdirectory(infiniband-diags)
add_subdirectory(infiniband-diags/scripts)
add_subdirectory(infiniband-diags/man)

if (CYTHON_EXECUTABLE)
  add_subdirectory(pyverbs)
  add_subdirectory(tests)
endif()

# Binaries
if (NOT NL_KIND EQUAL 0)
  add_subdirectory(ibacm) # NO SPARSE
endif()

if (NOT NL_KIND EQUAL 0)
  add_subdirectory(iwpmd)
endif()
add_subdirectory(libibumad/tests)
add_subdirectory(libibverbs/examples)
add_subdirectory(librdmacm/examples)
if (UDEV_FOUND)
  add_subdirectory(rdma-ndd)
endif()
add_subdirectory(srp_daemon)

ibverbs_finalize()
rdma_finalize_libs()

#-------------------------
# Display a summary
# Only report things that are non-ideal.
message(STATUS "Missing Optional Items:")
if (NOT HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE)
  message(STATUS " Compiler attribute always_inline NOT supported")
endif()
if (NOT HAVE_FUNC_ATTRIBUTE_IFUNC)
  message(STATUS " Compiler attribute ifunc NOT supported")
endif()
if (NOT HAVE_FUNC_ATTRIBUTE_SYMVER)
  message(STATUS " Compiler attribute symver NOT supported, can not use LTO")
endif()
if (NOT HAVE_COHERENT_DMA)
  message(STATUS " Architecture NOT able to do coherent DMA (check util/udma_barrier.h) some providers disabled!")
endif()
if (NOT HAVE_STDATOMIC)
  message(STATUS " C11 stdatomic.h NOT available (old compiler)")
endif()
if (NOT HAVE_STATIC_ASSERT)
  message(STATUS " C11 static_assert NOT available (old compiler)")
endif()
if (NOT HAVE_WORKING_STRICT_ALIASING)
  message(STATUS " Compiler cannot do strict aliasing")
endif()
if (NOT HAVE_VALGRIND_MEMCHECK)
  message(STATUS " Valgrind memcheck.h NOT enabled")
endif()
if (NOT HAVE_VALGRIND_DRD)
  message(STATUS " Valgrind drd.h NOT enabled")
endif()
if (NL_KIND EQUAL 0)
  message(STATUS " neighbour resolution NOT enabled")
else()
  if (NOT HAVE_WORKING_IF_H)
    message(STATUS " netlink/route/link.h and net/if.h NOT co-includable (old headers)")
  endif()
endif()
if (NO_MAN_PAGES)
  message(STATUS " man pages NOT built")
else()
  if (NOT PANDOC_FOUND)
    if (NOT EXISTS "${CMAKE_SOURCE_DIR}/buildlib/pandoc-prebuilt")
      message(STATUS " pandoc NOT found and NO prebuilt man pages. 'install' disabled")
    else()
      message(STATUS " pandoc NOT found (using prebuilt man pages)")
    endif()
  endif()
  if (NOT RST2MAN_FOUND)
    if (NOT EXISTS "${CMAKE_SOURCE_DIR}/buildlib/pandoc-prebuilt")
      message(STATUS " rst2man NOT found and NO prebuilt man pages. 'install' disabled")
    else()
      message(STATUS " rst2man NOT found (using prebuilt man pages)")
    endif()
  endif()
endif()
if (NOT CYTHON_EXECUTABLE)
  message(STATUS " cython NOT found (disabling pyverbs)")
endif()
if (NOT SYSTEMD_FOUND)
  message(STATUS " libsystemd NOT found (disabling features)")
endif()
if (NOT UDEV_FOUND)
  message(STATUS " libudev NOT found (disabling features)")
endif()
if (NOT HAVE_C_WARNINGS)
  message(STATUS " extended C warnings NOT supported")
endif()
if (NOT HAVE_NO_STRICT_ALIASING)
  message(STATUS " -fno-strict-aliasing NOT supported")
endif()
if (NOT HAVE_C_WORKING_MISSING_FIELD_INITIALIZERS)
  message(STATUS " -Wmissing-field-initializers does NOT work")
endif()
if (NOT HAVE_C_WORKING_SHADOW)
  message(STATUS " -Wshadow does NOT work")
endif()
if (NOT HAVE_C_WREDUNDANT_DECLS)
  message(STATUS " -Wredundant-decls does NOT work")
endif()
if (NOT HAVE_GLIBC_UAPI_COMPAT)
  message(STATUS " libc netinet/in.h and linux/in.h do NOT coexist")
endif()
if (NOT HAVE_TARGET_SSE)
  message(STATUS " attribute(target(\"sse\")) does NOT work")
endif()
if (NOT DRM_INCLUDE_DIRS)
  message(STATUS " DMABUF NOT supported (disabling some tests)")
endif()
