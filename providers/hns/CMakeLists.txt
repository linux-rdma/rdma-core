if (ENABLE_LTTNG AND LTTNGUST_FOUND)
  set(TRACE_FILE hns_roce_u_trace.c)
endif()

rdma_shared_provider(hns libhns.map
  1 1.0.${PACKAGE_VERSION}
  ${TRACE_FILE}
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

if (ENABLE_LTTNG AND LTTNGUST_FOUND)
  target_include_directories(hns PUBLIC ".")
  target_link_libraries(hns LINK_PRIVATE LTTng::UST)
endif()
