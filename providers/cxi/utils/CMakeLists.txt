rdma_executable(cxi_telem cxi_telem.c)
target_link_libraries(cxi_telem LINK_PRIVATE cxiverbs ibverbs)

rdma_executable(cxi_launcher cxi_launcher.c)
target_link_libraries(cxi_launcher LINK_PRIVATE cxiverbs ibverbs ${COMMON_LIBS})