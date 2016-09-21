# Shared example files
add_library(rdmacm_tools STATIC
  common.c
  )

rdma_executable(cmtime cmtime.c)
target_link_libraries(cmtime rdmacm ${CMAKE_THREAD_LIBS_INIT} rdmacm_tools)

rdma_executable(mckey mckey.c)
target_link_libraries(mckey rdmacm ${CMAKE_THREAD_LIBS_INIT})

rdma_executable(rcopy rcopy.c)
target_link_libraries(rcopy rdmacm)

rdma_executable(rdma_client rdma_client.c)
target_link_libraries(rdma_client rdmacm)

rdma_executable(rdma_server rdma_server.c)
target_link_libraries(rdma_server rdmacm)

rdma_executable(rdma_xclient rdma_xclient.c)
target_link_libraries(rdma_xclient rdmacm)

rdma_executable(rdma_xserver rdma_xserver.c)
target_link_libraries(rdma_xserver rdmacm)

rdma_executable(riostream riostream.c)
target_link_libraries(riostream rdmacm rdmacm_tools)

rdma_executable(rping rping.c)
target_link_libraries(rping rdmacm ${CMAKE_THREAD_LIBS_INIT})

rdma_executable(rstream rstream.c)
target_link_libraries(rstream rdmacm rdmacm_tools)

rdma_executable(ucmatose cmatose.c)
target_link_libraries(ucmatose rdmacm rdmacm_tools)

rdma_executable(udaddy udaddy.c)
target_link_libraries(udaddy rdmacm rdmacm_tools)

rdma_executable(udpong udpong.c)
target_link_libraries(udpong rdmacm rdmacm_tools)
