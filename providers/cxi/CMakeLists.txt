# Named cxiverbs (not cxi) to avoid colliding with the separate libcxi.so
# built by the HPE libcxi project, which links against this via cxidv.h.
rdma_shared_provider(cxiverbs libcxiverbs.map
  1 1.0.${PACKAGE_VERSION}
  cxi.c
  cxi_telem.c
  verbs.c
  )

publish_headers(infiniband
  cxidv.h
  cxidv_telem.h
  )

add_subdirectory(tests)

add_subdirectory(utils)

rdma_pkg_config("cxiverbs" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
