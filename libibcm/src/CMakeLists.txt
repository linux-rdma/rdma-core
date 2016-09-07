publish_headers(infiniband
  ../include/infiniband/cm.h
  )

rdma_library(ibcm libibcm.map
  # See Documentation/versioning.md
  1 1.0.${PACKAGE_VERSION}
  cm.c
  )
target_link_libraries(ibcm LINK_PUBLIC ibverbs)
