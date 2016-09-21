set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NO_STRICT_ALIASING_FLAGS}")

# Shared example files
add_library(ibverbs_tools STATIC
  pingpong.c
  )

rdma_executable(ibv_asyncwatch asyncwatch.c)
target_link_libraries(ibv_asyncwatch ibverbs)

rdma_executable(ibv_devices device_list.c)
target_link_libraries(ibv_devices ibverbs)

rdma_executable(ibv_devinfo devinfo.c)
target_link_libraries(ibv_devinfo ibverbs)

rdma_executable(ibv_rc_pingpong rc_pingpong.c)
target_link_libraries(ibv_rc_pingpong ibverbs ibverbs_tools)

rdma_executable(ibv_srq_pingpong srq_pingpong.c)
target_link_libraries(ibv_srq_pingpong ibverbs ibverbs_tools)

rdma_executable(ibv_uc_pingpong uc_pingpong.c)
target_link_libraries(ibv_uc_pingpong ibverbs ibverbs_tools)

rdma_executable(ibv_ud_pingpong ud_pingpong.c)
target_link_libraries(ibv_ud_pingpong ibverbs ibverbs_tools)

rdma_executable(ibv_xsrq_pingpong xsrq_pingpong.c)
target_link_libraries(ibv_xsrq_pingpong ibverbs ibverbs_tools)
