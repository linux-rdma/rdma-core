set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NO_STRICT_ALIASING_FLAGS}")

rdma_provider(cxgb4
  cq.c
  dev.c
  qp.c
  verbs.c
)
