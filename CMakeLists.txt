# COPYRIGHT (c) 2016 Obsidian Research Corporation. See COPYING file
# Run cmake as:
#  mkdir build
#  cmake -GNinja ..
#  ninja
#
# Common options passed to cmake are:
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

cmake_minimum_required(VERSION 2.8.11 FATAL_ERROR)
project(RDMA C)

# CMake likes to use -rdynamic too much, they fixed it in 3.4.
if(POLICY CMP0065)
  cmake_policy(SET CMP0065 NEW)
else()
  # .. but we really do want to opt out.
  string(REPLACE "-rdynamic" "" CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "${CMAKE_SHARED_LIBRARY_LINK_C_FLAGS}")
endif()

set(PACKAGE_NAME "RDMA")

# See Documentation/versioning.md
set(PACKAGE_VERSION "11")

#-------------------------
# Basic standard paths
include(GNUInstallDirs)
# C include root
set(BUILD_INCLUDE ${CMAKE_BINARY_DIR}/include)
# Executables
set(BUILD_BIN ${CMAKE_BINARY_DIR}/bin)
# Libraries
set(BUILD_LIB ${CMAKE_BINARY_DIR}/lib)

# Location to place provider .driver files
set(CONFIG_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/libibverbs.d")
set(CMAKE_INSTALL_INITDDIR "${CMAKE_INSTALL_SYSCONFDIR}/init.d"
  CACHE PATH "Location for init.d files")
set(CMAKE_INSTALL_SYSTEMD_SERVICEDIR "${CMAKE_INSTALL_PREFIX}/lib/systemd"
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

#-------------------------
# Load CMake components
set(BUILDLIB "${CMAKE_SOURCE_DIR}/buildlib")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${BUILDLIB}")

include(FindPkgConfig)
include(CheckCCompilerFlag)
include(CheckIncludeFile)
include(CheckTypeSize)
include(RDMA_EnableCStd)
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

# Require GNU99 mode
RDMA_EnableCStd()

# Extra warnings. Turn on -Wextra to keep aware of interesting developments from gcc,
# but turn off some that are not terribly useful for this source.
# FIXME: I wonder how many of the signed compares are bugs?
RDMA_AddOptCFlag(CMAKE_C_FLAGS HAVE_C_WARNINGS
  "-Wall -Wextra -Wno-sign-compare -Wno-unused-parameter")

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
 inline __attribute__((always_inline)) int foo(void) {return 0;}
 int main(int argc,const char *argv[]) { return foo(); }"
  HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE
  FAIL_REGEX "warning")

# Enable development support features
# Prune unneeded shared libraries during linking
RDMA_AddOptCFlag(CMAKE_EXE_LINKER_FLAGS SUPPORTS_AS_NEEDED "-Wl,--as-needed")
RDMA_AddOptCFlag(CMAKE_SHARED_LINKER_FLAGS SUPPORTS_AS_NEEDED "-Wl,--as-needed")
RDMA_AddOptCFlag(CMAKE_MODULE_LINKER_FLAGS SUPPORTS_AS_NEEDED "-Wl,--as-needed")

# Ensure all shared ELFs have fully described linking
RDMA_AddOptCFlag(CMAKE_EXE_LINKER_FLAGS SUPPORTS_NO_UNDEFINED "-Wl,--no-undefined")
RDMA_AddOptCFlag(CMAKE_SHARED_LINKER_FLAGS SUPPORTS_NO_UNDEFINED "-Wl,--no-undefined")

# Enable gold linker - gold has different linking checks
#RDMA_AddOptCFlag(CMAKE_EXE_LINKER_FLAGS SUPPORTS_NO_UNDEFINED "-fuse-ld=gold")
#RDMA_AddOptCFlag(CMAKE_SHARED_LINKER_FLAGS SUPPORTS_NO_UNDEFINED "-fuse-ld=gold")
#RDMA_AddOptCFlag(CMAKE_MODULE_LINKER_FLAGS SUPPORTS_NO_UNDEFINED "-fuse-ld=gold")

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

# Statically determine sizeof(long), this is largely unnecessary, no new code
# should rely on this.
check_type_size("long" SIZEOF_LONG BUILTIN_TYPES_ONLY LANGUAGE C)

# Are our kernel headers new enough?
# If not replace them with built-in copies so we can continue to build.
CHECK_INCLUDE_FILE("rdma/rdma_user_rxe.h" HAVE_RDMA_USER_RXE)
RDMA_DoFixup("${HAVE_RDMA_USER_RXE}" "rdma/rdma_user_rxe.h")

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
# Libraries
add_subdirectory(libibumad/src)
add_subdirectory(libibumad/man)
add_subdirectory(libibverbs/src)
add_subdirectory(libibverbs/man)
add_subdirectory(librdmacm/src)
add_subdirectory(librdmacm/man)
add_subdirectory(libibcm/src)

# Providers
add_subdirectory(providers/cxgb3)
add_subdirectory(providers/cxgb4)
add_subdirectory(providers/hfi1verbs)
add_subdirectory(providers/i40iw)
add_subdirectory(providers/ipathverbs)
add_subdirectory(providers/mlx4)
add_subdirectory(providers/mlx5)
add_subdirectory(providers/mthca)
add_subdirectory(providers/nes)
add_subdirectory(providers/ocrdma)
add_subdirectory(providers/rxe)
add_subdirectory(providers/rxe/man)

# Binaries
add_subdirectory(ibacm)
if (NOT NL_KIND EQUAL 0)
  add_subdirectory(iwpmd)
endif()
add_subdirectory(libibcm/examples)
add_subdirectory(libibumad/tests)
add_subdirectory(libibverbs/examples)
add_subdirectory(librdmacm/examples)
add_subdirectory(srp_daemon)

rdma_finalize_libs()

#-------------------------
# Display a summary
# Only report things that are non-ideal.
message(STATUS "Missing Optional Items:")
if (NOT HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE)
  message(STATUS " Compiler attribute always_inline NOT supported")
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
endif()
if (NOT HAVE_RDMA_USER_RXE)
  message(STATUS " rdma/rdma_user_rxe.h NOT found (old system kernel headers)")
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
