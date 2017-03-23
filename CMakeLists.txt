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
#  -DKERNEL_DIR='.../linux' (default '')
#      If set use the kernel UAPI headers from this kernel source tree.

cmake_minimum_required(VERSION 2.8.11 FATAL_ERROR)
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
set(PACKAGE_VERSION "14")

#-------------------------
# Basic standard paths

# Override the CMAKE_INSTALL_ dirs to be under the build/ directory
if (IN_PLACE)
  set(CMAKE_INSTALL_SYSCONFDIR "${CMAKE_BINARY_DIR}/etc")
  set(CMAKE_INSTALL_BINDIR "${CMAKE_BINARY_DIR}/bin")
endif()

include(GNUInstallDirs)
# C include root
set(BUILD_INCLUDE ${CMAKE_BINARY_DIR}/include)
# Executables
set(BUILD_BIN ${CMAKE_BINARY_DIR}/bin)
# Libraries
set(BUILD_LIB ${CMAKE_BINARY_DIR}/lib)
# Used for IN_PLACE configuration
set(BUILD_ETC ${CMAKE_BINARY_DIR}/etc)

set(CMAKE_INSTALL_INITDDIR "${CMAKE_INSTALL_SYSCONFDIR}/init.d"
  CACHE PATH "Location for init.d files")
set(CMAKE_INSTALL_SYSTEMD_SERVICEDIR "${CMAKE_INSTALL_PREFIX}/lib/systemd/system"
  CACHE PATH "Location for systemd service files")

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

include(FindPkgConfig)
include(CheckCCompilerFlag)
include(CheckIncludeFile)
include(CheckTypeSize)
include(RDMA_EnableCStd)
include(RDMA_Sparse)
include(RDMA_BuildType)
include(RDMA_DoFixup)
include(publish_headers)
include(rdma_functions)

if (NOT DEFINED ENABLE_STATIC)
  set(ENABLE_STATIC "OFF" CACHE BOOL "Produce static linking libraries as well as shared libraries.")
endif()

#-------------------------
# Setup the basic C compiler
RDMA_BuildType()
include_directories(${BUILD_INCLUDE})

RDMA_CheckSparse()

# Require GNU99 mode
RDMA_EnableCStd()

# Extra warnings. Turn on -Wextra to keep aware of interesting developments from gcc,
# but turn off some that are not terribly useful for this source.
# FIXME: I wonder how many of the signed compares are bugs?
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WARNINGS
  "-Wall -Wextra -Wno-sign-compare -Wno-unused-parameter")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WMISSING_PROTOTYPES "-Wmissing-prototypes")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WMISSING_DECLARATIONS "-Wmissing-declarations")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WWRITE_STRINGS "-Wwrite-strings")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WFORMAT_2 "-Wformat=2")

# At some point after 4.4 gcc fixed shadow to ignore function vs variable
# conflicts
set(SAFE_CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_FLAGS "-Wshadow")
CHECK_C_SOURCE_COMPILES("
 #include <unistd.h>
 int main(int argc,const char *argv[]) { int access = 1; return access; }"
  HAVE_C_WORKING_SHADOW
  FAIL_REGEX "warning")
if (HAVE_C_WORKING_SHADOW)
  RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WORKING_SHADOW "-Wshadow")
endif()
set(CMAKE_REQUIRED_FLAGS "${SAFE_CMAKE_REQUIRED_FLAGS}")

# At some point around 5.4 gcc fixed missing-field-initializers to ignore this
# common idiom we use extensively. Since this is a useful warning for
# developers try and leave it on if the compiler supports it.
CHECK_C_SOURCE_COMPILES("
 struct foo { int a; int b; };
 int main(int argc,const char *argv[]) { struct foo tmp = {}; return tmp.a; }"
  HAVE_C_WORKING_MISSING_FIELD_INITIALIZERS
  FAIL_REGEX "warning")
if (NOT HAVE_C_WORKING_MISSING_FIELD_INITIALIZERS)
  RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WNO_MISSING_FIELD_INITIALIZERS "-Wno-missing-field-initializers")
endif()

# Check that the compiler supports -fno-strict-aliasing.
# The use of this flag in the source is discouraged
set(NO_STRICT_ALIASING_FLAGS "")
RDMA_AddOptCFlag(NO_STRICT_ALIASING_FLAGS HAVE_NO_STRICT_ALIASING
  "-fno-strict-aliasing")

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
  message(FATAL_ERROR "O_CLOEXEC/SOCK_CLOEXEC/fopen(..,\"e\") support is required but not found")
endif()

# always_inline is supported
CHECK_C_SOURCE_COMPILES("
 int foo(void);
 inline __attribute__((always_inline)) int foo(void) {return 0;}
 int main(int argc,const char *argv[]) { return foo(); }"
  HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE
  FAIL_REGEX "warning")

# Provide a shim if C11 stdatomic.h is not supported.
if (NOT HAVE_SPARSE)
  CHECK_INCLUDE_FILE("stdatomic.h" HAVE_STDATOMIC)
  RDMA_DoFixup("${HAVE_STDATOMIC}" "stdatomic.h")
endif()

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

#-------------------------
# Find libraries
# pthread
FIND_PACKAGE (Threads REQUIRED)

# libnl
if (NOT DEFINED ENABLE_RESOLVE_NEIGH)
  set(ENABLE_RESOLVE_NEIGH "ON" CACHE BOOL "Enable internal resolution of neighbours for Etherent")
endif()
if (ENABLE_RESOLVE_NEIGH)
  # FIXME use of pkgconfig is discouraged
  pkg_check_modules(NL3 libnl-3.0 libnl-route-3.0)
  if (NL3_FOUND)
    set(NL_KIND 3)
    set(NL_INCLUDE_DIRS ${NL3_INCLUDE_DIRS})
    set(NL_LIBRARIES ${NL3_LIBRARIES})
  else()
    # FIXME: I don't know why we have this fallback, all supported distros
    # have libnl3
    pkg_check_modules(NL1 libnl-1)
    if (NL1_FOUND)
      set(NL_KIND 1)
      set(NL_INCLUDE_DIRS ${NL1_INCLUDE_DIRS})
      set(NL_LIBRARIES ${NL1_LIBRARIES})
    else()
      message(FATAL_ERROR "Cannot find libnl-3.0 or libnl-1")
    endif()
  endif()

  include_directories(${NL_INCLUDE_DIRS})
else()
  set(NL_KIND 0)
  set(NL_LIBRARIES "")
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

include(RDMA_LinuxHeaders)

# Determine if this arch supports cache coherent DMA. This isn't really an
# arch specific property, but for our purposes arches that do not support it
# also do not define wmb/etc which breaks our compile.
CHECK_C_SOURCE_COMPILES("
#include \"${CMAKE_CURRENT_SOURCE_DIR}/util/udma_barrier.h\"
 int main(int argc,const char *argv[]) {return 0;}"
  HAVE_COHERENT_DMA)

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

#-------------------------
# Final warning flags

# Old version of cmake used 'main(){..}' as their test program which breaks with -Werror.
# So set this flag last.
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WSTRICT_PROTOTYPES "-Wstrict-prototypes")
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WOLD_STYLE_DEFINITION "-Wold-style-definition")

# Old versions of libnl have a duplicated rtnl_route_put, disbale the warning on those
# systems
if (NOT NL_KIND EQUAL 0)
  set(SAFE_CMAKE_REQUIRED_INCLUDES "${CMAKE_REQUIRED_INCLUDES}")
  set(SAFE_CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_INCLUDES "${NL_INCLUDE_DIRS}")
  set(CMAKE_REQUIRED_FLAGS "-Wredundant-decls")
  CHECK_C_SOURCE_COMPILES("
 #include <netlink/route/route.h>
 int main(int argc,const char *argv[]) { return 0; }"
  HAVE_C_WREDUNDANT_DECLS
  FAIL_REGEX "warning")
  set(CMAKE_REQUIRED_INCLUDES "${SAFE_CMAKE_REQUIRED_INCLUDES}")
  set(CMAKE_REQUIRED_FLAGS "${SAFE_CMAKE_REQUIRED_FLAGS}")
endif()
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WREDUNDANT_DECLS "-Wredundant-decls")

#-------------------------
# Build Prep
# Write out a git ignore file to the build directory if it isn't the source
# directory. For developer convenience
if (NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
  file(WRITE ${CMAKE_BINARY_DIR}/.gitignore "*")
endif()

configure_file("${BUILDLIB}/config.h.in" "${BUILD_INCLUDE}/config.h" ESCAPE_QUOTES @ONLY)

#-------------------------
# Sub-directories
add_subdirectory(ccan)
add_subdirectory(util)
add_subdirectory(Documentation)
# Libraries
add_subdirectory(libibumad)
add_subdirectory(libibumad/man)
add_subdirectory(libibverbs)
add_subdirectory(libibverbs/man)
add_subdirectory(librdmacm)
add_subdirectory(librdmacm/man)
add_subdirectory(libibcm)

# Providers
if (HAVE_COHERENT_DMA)
add_subdirectory(providers/cxgb3) # NO SPARSE
add_subdirectory(providers/cxgb4) # NO SPARSE
add_subdirectory(providers/hns) # NO SPARSE
add_subdirectory(providers/i40iw) # NO SPARSE
add_subdirectory(providers/mlx4) # NO SPARSE
add_subdirectory(providers/mlx5) # NO SPARSE
add_subdirectory(providers/mlx5/man) # NO SPARSE
add_subdirectory(providers/mthca) # NO SPARSE
add_subdirectory(providers/nes) # NO SPARSE
add_subdirectory(providers/ocrdma) # NO SPARSE
add_subdirectory(providers/qedr) # NO SPARSE
add_subdirectory(providers/vmw_pvrdma) # NO SPARSE
endif()

add_subdirectory(providers/hfi1verbs) # NO SPARSE
add_subdirectory(providers/ipathverbs) # NO SPARSE
add_subdirectory(providers/rxe) # NO SPARSE
add_subdirectory(providers/rxe/man) # NO SPARSE

# Binaries
add_subdirectory(ibacm) # NO SPARSE
if (NOT NL_KIND EQUAL 0)
  add_subdirectory(iwpmd)
endif()
add_subdirectory(libibcm/examples)
add_subdirectory(libibumad/tests)
add_subdirectory(libibverbs/examples)
add_subdirectory(librdmacm/examples)
if (UDEV_FOUND)
  add_subdirectory(rdma-ndd)
endif()
add_subdirectory(srp_daemon)

rdma_finalize_libs()

#-------------------------
# Display a summary
# Only report things that are non-ideal.
message(STATUS "Missing Optional Items:")
if (NOT HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE)
  message(STATUS " Compiler attribute always_inline NOT supported")
endif()
if (NOT HAVE_COHERENT_DMA)
  message(STATUS " Architecture NOT able to do coherent DMA (check libibverbs/arch.h) some providers disabled!")
endif()
if (NOT HAVE_STDATOMIC)
  message(STATUS " C11 stdatomic.h NOT available (old compiler)")
endif()
if (NOT HAVE_VALGRIND_MEMCHECK)
  message(STATUS " Valgrind memcheck.h NOT enabled")
endif()
if (NOT HAVE_VALGRIND_DRD)
  message(STATUS " Valgrind drd.h NOT enabled")
endif()
if (NL_KIND EQUAL 1)
  message(STATUS " libnl 3 NOT found (using libnl 1 compat)")
endif()
if (NL_KIND EQUAL 0)
  message(STATUS " neighbour resolution NOT enabled")
else()
  if (NOT HAVE_WORKING_IF_H)
    message(STATUS " netlink/route/link.h and net/if.h NOT co-includable (old headers)")
  endif()
endif()
if (NOT UDEV_FOUND)
  message(STATUS " libudev NOT found (disabling features)")
endif()
rdma_report_missing_kheaders()
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
