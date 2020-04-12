publish_headers(infiniband
  umad.h
  umad_cm.h
  umad_sa.h
  umad_sa_mcm.h
  umad_sm.h
  umad_str.h
  umad_types.h
  )

rdma_library(ibumad libibumad.map
  # See Documentation/versioning.md
  3 3.2.${PACKAGE_VERSION}
  sysfs.c
  umad.c
  umad_str.c
  )

rdma_pkg_config("ibumad" "" "")
