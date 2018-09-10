rdma_shared_provider(mlx4 libmlx4.map
  1 1.0.${PACKAGE_VERSION}
  buf.c
  cq.c
  dbrec.c
  mlx4.c
  qp.c
  srq.c
  verbs.c
)

publish_headers(infiniband
  mlx4dv.h
)

install(FILES "mlx4.conf" DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/modprobe.d/")

rdma_pkg_config("mlx4" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
