publish_headers(rdma
  rdma_cma.h
  rdma_cma_abi.h
  rdma_verbs.h
  rsocket.h
  )
publish_headers(infiniband
  ib.h
  )

rdma_library(rdmacm librdmacm.map
  # See Documentation/versioning.md
  1 1.2.${PACKAGE_VERSION}
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

# The preload library is a bit special, it needs to be open coded
# Since it is a LD_PRELOAD it has no soname, and is installed in sub dir
add_library(rspreload MODULE
  preload.c
  indexer.c
  )
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
