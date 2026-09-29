# Shared example files
add_library(rdmacm_tools STATIC
  common.c
  )
target_link_libraries(rdmacm_tools LINK_PRIVATE ${CMAKE_THREAD_LIBS_INIT})

rdma_executable(cmtime cmtime.c)
target_link_libraries(cmtime LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(mckey mckey.c)
target_link_libraries(mckey LINK_PRIVATE rdmacm ${CMAKE_THREAD_LIBS_INIT} rdmacm_tools)

rdma_executable(rcopy rcopy.c)
target_link_libraries(rcopy LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(rdma_client rdma_client.c)
target_link_libraries(rdma_client LINK_PRIVATE rdmacm)

rdma_executable(rdma_server rdma_server.c)
target_link_libraries(rdma_server LINK_PRIVATE rdmacm)

rdma_executable(rdma_xclient rdma_xclient.c)
target_link_libraries(rdma_xclient LINK_PRIVATE rdmacm)

rdma_executable(rdma_xserver rdma_xserver.c)
target_link_libraries(rdma_xserver LINK_PRIVATE rdmacm)

rdma_executable(riostream riostream.c)
target_link_libraries(riostream LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(rping rping.c)
target_link_libraries(rping LINK_PRIVATE rdmacm ${CMAKE_THREAD_LIBS_INIT} rdmacm_tools)

rdma_executable(rstream rstream.c)
target_link_libraries(rstream LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(ucmatose cmatose.c)
target_link_libraries(ucmatose LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(udaddy udaddy.c)
target_link_libraries(udaddy LINK_PRIVATE rdmacm rdmacm_tools)

rdma_executable(udpong udpong.c)
target_link_libraries(udpong LINK_PRIVATE rdmacm rdmacm_tools)

if (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  find_package(epoll-shim REQUIRED)
  target_include_directories(rdmacm_tools PRIVATE epoll-shim::epoll-shim)
  target_link_libraries(rdmacm_tools PRIVATE epoll-shim::epoll-shim)
  target_include_directories(cmtime PRIVATE epoll-shim::epoll-shim)
  target_link_libraries(cmtime PRIVATE epoll-shim::epoll-shim)
  target_include_directories(mckey PRIVATE epoll-shim::epoll-shim)
  target_link_libraries(mckey PRIVATE epoll-shim::epoll-shim)
  target_include_directories(rcopy PRIVATE epoll-shim::epoll-shim)
  target_link_libraries(rcopy PRIVATE epoll-shim::epoll-shim)
  target_include_directories(riostream PRIVATE epoll-shim::epoll-shim)
  target_link_libraries(riostream PRIVATE epoll-shim::epoll-shim)
  target_include_directories(rping PRIVATE epoll-shim::epoll-shim)
  target_link_libraries(rping PRIVATE epoll-shim::epoll-shim)
  target_include_directories(rstream PRIVATE epoll-shim::epoll-shim)
  target_link_libraries(rstream PRIVATE epoll-shim::epoll-shim)
  target_include_directories(ucmatose PRIVATE epoll-shim::epoll-shim)
  target_link_libraries(ucmatose PRIVATE epoll-shim::epoll-shim)
  target_include_directories(udaddy PRIVATE epoll-shim::epoll-shim)
  target_link_libraries(udaddy PRIVATE epoll-shim::epoll-shim)
  target_include_directories(udpong PRIVATE epoll-shim::epoll-shim)
  target_link_libraries(udpong PRIVATE epoll-shim::epoll-shim)
endif()
