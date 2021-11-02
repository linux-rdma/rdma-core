rdma_shared_provider(mana libmana.map
  1 1.0.${PACKAGE_VERSION}
  mana.c
  manadv.c
  qp.c
  wq.c
)

publish_headers(infiniband
  manadv.h
)

rdma_pkg_config("mana" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
