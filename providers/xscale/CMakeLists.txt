rdma_shared_provider(xscale libxsc.map
  1 1.24.${PACKAGE_VERSION}
  xscale.c
  verbs.c
  cq.c
  buf.c
)

rdma_pkg_config("xscale" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")

