# Shared example files
add_library(rdmacm_tools STATIC
  common.c
  )
rdma_target_link_libraries(rdmacm_tools LINK_PRIVATE ${CMAKE_THREAD_LIBS_INIT})

rdma_executable(cmtime cmtime.c)
rdma_target_link_libraries(cmtime LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(mckey mckey.c)
rdma_target_link_libraries(mckey LINK_PRIVATE rdmacm ${CMAKE_THREAD_LIBS_INIT} rdmacm_tools)

rdma_executable(rcopy rcopy.c)
rdma_target_link_libraries(rcopy LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(rdma_client rdma_client.c)
rdma_target_link_libraries(rdma_client LINK_PRIVATE rdmacm)

rdma_executable(rdma_server rdma_server.c)
rdma_target_link_libraries(rdma_server LINK_PRIVATE rdmacm)

rdma_executable(rdma_xclient rdma_xclient.c)
rdma_target_link_libraries(rdma_xclient LINK_PRIVATE rdmacm)

rdma_executable(rdma_xserver rdma_xserver.c)
rdma_target_link_libraries(rdma_xserver LINK_PRIVATE rdmacm)

rdma_executable(riostream riostream.c)
rdma_target_link_libraries(riostream LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(rping rping.c)
rdma_target_link_libraries(rping LINK_PRIVATE rdmacm ${CMAKE_THREAD_LIBS_INIT} rdmacm_tools)

rdma_executable(rstream rstream.c)
rdma_target_link_libraries(rstream LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(ucmatose cmatose.c)
rdma_target_link_libraries(ucmatose LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(udaddy udaddy.c)
rdma_target_link_libraries(udaddy LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(udpong udpong.c)
rdma_target_link_libraries(udpong LINK_PRIVATE rdmacm rdmacm_tools)
