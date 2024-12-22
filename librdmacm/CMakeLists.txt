publish_headers(rdma
  rdma_cma.h
  rdma_cma_abi.h
  rdma_verbs.h
  rsocket.h
  )
publish_headers(infiniband
  acm.h
  ib.h
  )

rdma_library(rdmacm librdmacm.map
  # See Documentation/versioning.md
  1 1.5.${PACKAGE_VERSION}
  acm.c
  addrinfo.c
  cma.c
  indexer.c
  rsocket.c
  )
target_link_libraries(rdmacm LINK_PUBLIC ibverbs)
target_link_libraries(rdmacm LINK_PRIVATE
  ${NL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${RT_LIBRARIES}
  )

# When building without LFS (_FILE_OFFSET_BITS != 64), we may need to wrap
# fcntl64/sendfile64. Only do so if the system libc actually provides them
set(CMAKE_REQUIRED_QUIET 1)
set(SAVE_DEFS "${CMAKE_REQUIRED_DEFINITIONS}")
set(CMAKE_REQUIRED_DEFINITIONS "")
check_c_source_compiles("
#include <fcntl.h>
#include <sys/sendfile.h>
int main(void) {
  (void)&fcntl64;
  (void)&sendfile64;
  return 0;
}
" RDMA_PRELOAD_HAVE_64)
set(CMAKE_REQUIRED_DEFINITIONS "${SAVE_DEFS}")
set(CMAKE_REQUIRED_QUIET 0)
if(RDMA_PRELOAD_HAVE_64)
  set(RDMA_PRELOAD_HAVE_LFS_WRAPPER_SYMS 1)
else()
  set(RDMA_PRELOAD_HAVE_LFS_WRAPPER_SYMS 0)
endif()

# Detect at configure time if fcntl64/sendfile64 is declared so we can
# add our forward declarations only when needed.
set(RDMA_PRELOAD_FCNTL64_IN_HEADER 0)
set(RDMA_PRELOAD_SENDFILE64_IN_HEADER 0)
if(RDMA_PRELOAD_HAVE_LFS_WRAPPER_SYMS)
  set(CMAKE_REQUIRED_QUIET 1)
  set(SAVE_FLAGS "${CMAKE_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_FLAGS "${CMAKE_C_FLAGS}")
  check_c_source_compiles("
#define _GNU_SOURCE
#include <fcntl.h>
int fcntl64(int socket, int cmd, ...) { (void)socket;(void)cmd; return 0; }
" RDMA_PRELOAD_FCNTL64_DECLARED_IN_HEADER)
  if(RDMA_PRELOAD_FCNTL64_DECLARED_IN_HEADER)
    set(RDMA_PRELOAD_FCNTL64_IN_HEADER 1)
  endif()
  check_c_source_compiles("
#define _GNU_SOURCE
#include <sys/sendfile.h>
#include <sys/types.h>
ssize_t sendfile64(int out_fd, int in_fd, off64_t *offset64, size_t count) {
  (void)out_fd;(void)in_fd;(void)offset64;(void)count; return 0;
}
" RDMA_PRELOAD_SENDFILE64_DECLARED_IN_HEADER)
  if(RDMA_PRELOAD_SENDFILE64_DECLARED_IN_HEADER)
    set(RDMA_PRELOAD_SENDFILE64_IN_HEADER 1)
  endif()
  set(CMAKE_REQUIRED_FLAGS "${SAVE_FLAGS}")
  set(CMAKE_REQUIRED_QUIET 0)
endif()

# The preload library is a bit special, it needs to be open coded
# Since it is a LD_PRELOAD it has no soname, and is installed in sub dir
add_library(rspreload MODULE
  preload.c
  indexer.c
  )
target_compile_definitions(rspreload PRIVATE
  RDMA_PRELOAD_HAVE_64=${RDMA_PRELOAD_HAVE_LFS_WRAPPER_SYMS}
  RDMA_PRELOAD_FCNTL64_IN_HEADER=${RDMA_PRELOAD_FCNTL64_IN_HEADER}
  RDMA_PRELOAD_SENDFILE64_IN_HEADER=${RDMA_PRELOAD_SENDFILE64_IN_HEADER})
# Even though this is a module we still want to use Wl,--no-undefined
set_target_properties(rspreload PROPERTIES LINK_FLAGS ${CMAKE_SHARED_LINKER_FLAGS})
set_target_properties(rspreload PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${BUILD_LIB}")
rdma_set_library_map(rspreload librspreload.map)
target_link_libraries(rspreload LINK_PRIVATE
  rdmacm
  ${CMAKE_THREAD_LIBS_INIT}
  ${CMAKE_DL_LIBS}
)
install(TARGETS rspreload DESTINATION "${CMAKE_INSTALL_LIBDIR}/rsocket/")

# These are for compat with old packaging, these name should not be used.
# FIXME: Maybe we can get rid of them?
rdma_install_symlink("librspreload.so" "${CMAKE_INSTALL_LIBDIR}/rsocket/librspreload.so.1")
rdma_install_symlink("librspreload.so" "${CMAKE_INSTALL_LIBDIR}/rsocket/librspreload.so.1.0.0")

if (ENABLE_STATIC)
  if (NOT NL_KIND EQUAL 0)
    set(REQUIRES "libnl-3.0, libnl-route-3.0, ")
  endif()
endif()
rdma_pkg_config("rdmacm" "${REQUIRES}libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
