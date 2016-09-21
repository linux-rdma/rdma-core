rdma_test_executable(cmpost cmpost.c)
target_link_libraries(cmpost ibcm rdmacm)
