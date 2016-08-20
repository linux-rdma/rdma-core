publish_headers(rdma
  ../include/rdma/rdma_cma.h
  ../include/rdma/rdma_cma_abi.h
  ../include/rdma/rdma_verbs.h
  ../include/rdma/rsocket.h
  )
publish_headers(infiniband
  ../include/infiniband/ib.h
  )

rdma_library(rdmacm librdmacm.map 1 1.0.0
  acm.c
  addrinfo.c
  cma.c
  indexer.c
  rsocket.c
  )
target_link_libraries(rdmacm LINK_PUBLIC ibverbs)
target_link_libraries(rdmacm LINK_PRIVATE ${CMAKE_THREAD_LIBS_INIT})

# The preload library is a bit special, it needs to be open coded
# Since it is a LD_PRELOAD it has no soname, and is installed in sub dir
add_library(rspreload SHARED
  preload.c
  indexer.c
  )
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
