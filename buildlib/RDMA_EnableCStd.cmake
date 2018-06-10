# COPYRIGHT (c) 2016 Obsidian Research Corporation.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.

# cmake does not have way to do this even slightly sanely until CMP0056
function(RDMA_CHECK_C_LINKER_FLAG FLAG CACHE_VAR)
  set(SAFE_CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
  set(SAFE_CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")

  if (POLICY CMP0056)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${FLAG}")
  else()
    set(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES} ${FLAG}")
  endif()

  CHECK_C_COMPILER_FLAG("" ${CACHE_VAR})

  set(CMAKE_EXE_LINKER_FLAGS "${SAFE_CMAKE_EXE_LINKER_FLAGS}")
  set(CMAKE_REQUIRED_LIBRARIES "${SAFE_CMAKE_REQUIRED_LIBRARIES}")
endfunction()

# Test if the CC compiler supports the linker flag and if so add it to TO_VAR
function(RDMA_AddOptLDFlag TO_VAR CACHE_VAR FLAG)
  RDMA_CHECK_C_LINKER_FLAG("${FLAG}" ${CACHE_VAR})
  if (${CACHE_VAR})
    SET(${TO_VAR} "${${TO_VAR}} ${FLAG}" PARENT_SCOPE)
  endif()
endfunction()

# Test if the CC compiler supports the flag and if so add it to TO_VAR
function(RDMA_AddOptCFlag TO_VAR CACHE_VAR FLAG)
  CHECK_C_COMPILER_FLAG("${FLAG}" ${CACHE_VAR})
  if (${CACHE_VAR})
    SET(${TO_VAR} "${${TO_VAR}} ${FLAG}" PARENT_SCOPE)
  endif()
endfunction()

# Enable the minimum required gnu11 standard in the compiler
# This was introduced in GCC 4.7
function(RDMA_EnableCStd)
  if (HAVE_SPARSE)
    # Sparse doesn't support gnu11, but doesn't fail if the option is present,
    # force gnu99 instead.
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99" PARENT_SCOPE)
    return()
  endif()

  if (CMAKE_VERSION VERSION_LESS "3.1")
    # Check for support of the usual flag
    CHECK_C_COMPILER_FLAG("-std=gnu11" SUPPORTS_GNU11)
    if (SUPPORTS_GNU11)
      SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11" PARENT_SCOPE)
    else()
      SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99" PARENT_SCOPE)
    endif()
  else()
    # Newer cmake can do this internally
    set(CMAKE_C_STANDARD 11 PARENT_SCOPE)
  endif()
endfunction()

function(RDMA_Check_Aliasing TO_VAR)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
  CHECK_C_SOURCE_COMPILES("
struct in6_addr {unsigned int u6_addr32[4];};
struct iphdr {unsigned int daddr;};
union ibv_gid {unsigned char raw[16];};

static void map_ipv4_addr_to_ipv6(struct in6_addr *ipv6) {ipv6->u6_addr32[0] = 0;}
static int set_ah_attr_by_ipv4(struct iphdr *ip4h)
{
	union ibv_gid sgid = {};
	map_ipv4_addr_to_ipv6((struct in6_addr *)&sgid);
	return 0;
}

int main(int argc, char *argv[])
{
	struct in6_addr a;
	struct iphdr h = {};
	map_ipv4_addr_to_ipv6(&a);
	return set_ah_attr_by_ipv4(&h);
}"
    HAVE_WORKING_STRICT_ALIASING
    FAIL_REGEX "warning")

  set(${TO_VAR} "${HAVE_WORKING_STRICT_ALIASING}" PARENT_SCOPE)
endfunction()

function(RDMA_Check_SSE TO_VAR)
  set(SSE_CHECK_PROGRAM "
#if defined(__i386__)
#include <string.h>
#include <xmmintrin.h>
int __attribute__((target(\"sse\"))) main(int argc, char *argv[])
{
	__m128 tmp = {};

	tmp = _mm_loadl_pi(tmp, (__m64 *)&main);
	_mm_storel_pi((__m64 *)&main, tmp);
	return memchr(&tmp, 0, sizeof(tmp)) == &tmp;
}
#else
int main(int argc, char *argv[])
{
	return 0;
}
#endif
")

  CHECK_C_SOURCE_COMPILES(
    "${SSE_CHECK_PROGRAM}"
    HAVE_TARGET_SSE
    FAIL_REGEX "warning")

  if(NOT HAVE_TARGET_SSE)
    # Older compiler, we can work around this by adding -msse instead of
    # relying on the function attribute.
    set(CMAKE_REQUIRED_FLAGS "-msse")
    CHECK_C_SOURCE_COMPILES(
      "${SSE_CHECK_PROGRAM}"
      NEED_MSSE_FLAG
      FAIL_REGEX "warning")
    set(CMAKE_REQUIRED_FLAGS)

    if(NEED_MSSE_FLAG)
      set(SSE_FLAGS "-msse" PARENT_SCOPE)
    else()
      message(FATAL_ERROR "Can not figure out how to turn on sse instructions for i386")
    endif()
  endif()
  set(${TO_VAR} "${HAVE_TARGET_SSE}" PARENT_SCOPE)
endFunction()
