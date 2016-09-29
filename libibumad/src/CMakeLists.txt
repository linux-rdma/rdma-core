publish_headers(infiniband
  ../include/infiniband/umad.h
  ../include/infiniband/umad_cm.h
  ../include/infiniband/umad_sa.h
  ../include/infiniband/umad_sm.h
  ../include/infiniband/umad_str.h
  ../include/infiniband/umad_types.h
  )

rdma_library(ibumad libibumad.map
  # See Documentation/versioning.md
  3 3.1.${PACKAGE_VERSION}
  sysfs.c
  umad.c
  umad_str.c
  )
