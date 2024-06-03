rdma_shared_provider(hns libhns.map
  1 1.0.${PACKAGE_VERSION}
  hns_roce_u.c
  hns_roce_u_buf.c
  hns_roce_u_db.c
  hns_roce_u_hw_v2.c
  hns_roce_u_verbs.c
)

publish_headers(infiniband
  hnsdv.h
)

rdma_pkg_config("hns" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
