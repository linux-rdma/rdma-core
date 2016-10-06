# Shared example files
add_library(ibverbs_tools STATIC
  pingpong.c
  )

rdma_executable(ibv_asyncwatch asyncwatch.c)
target_link_libraries(ibv_asyncwatch LINK_PRIVATE ibverbs)

rdma_executable(ibv_devices device_list.c)
target_link_libraries(ibv_devices LINK_PRIVATE ibverbs)

rdma_executable(ibv_devinfo devinfo.c)
target_link_libraries(ibv_devinfo LINK_PRIVATE ibverbs)

rdma_executable(ibv_rc_pingpong rc_pingpong.c)
target_link_libraries(ibv_rc_pingpong LINK_PRIVATE ibverbs ibverbs_tools)

rdma_executable(ibv_srq_pingpong srq_pingpong.c)
target_link_libraries(ibv_srq_pingpong LINK_PRIVATE ibverbs ibverbs_tools)

rdma_executable(ibv_uc_pingpong uc_pingpong.c)
target_link_libraries(ibv_uc_pingpong LINK_PRIVATE ibverbs ibverbs_tools)

rdma_executable(ibv_ud_pingpong ud_pingpong.c)
target_link_libraries(ibv_ud_pingpong LINK_PRIVATE ibverbs ibverbs_tools)

rdma_executable(ibv_xsrq_pingpong xsrq_pingpong.c)
target_link_libraries(ibv_xsrq_pingpong LINK_PRIVATE ibverbs ibverbs_tools)
