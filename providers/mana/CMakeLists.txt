rdma_shared_provider(mana libmana.map
  1 1.1.${PACKAGE_VERSION}
  mana.c
  manadv.c
  qp.c
  wq.c
  cq.c
  wr.c
)

# shadow_queue.h uses 64-bit atomics
target_link_libraries(mana LINK_PRIVATE ${ATOMIC_LIBRARIES})

publish_headers(infiniband
  manadv.h
)

rdma_pkg_config("mana" "libibverbs" "${CMAKE_THREAD_LIBS_INIT} ${ATOMIC_LIBRARIES}")
