rdma_shared_provider(xscale libxsc.map
  1 1.24.${PACKAGE_VERSION}
  xscale.c
  verbs.c
  cq.c
  qp.c
  buf.c
)

publish_headers(infiniband
  ../../kernel-headers/rdma/xsc_user_ioctl_verbs.h
  ../../kernel-headers/rdma/xsc_user_ioctl_cmds.h
  xsc_api.h
  xscdv.h
)

rdma_pkg_config("xscale" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
