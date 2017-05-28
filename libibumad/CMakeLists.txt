publish_headers(infiniband
  umad.h
  umad_cm.h
  umad_sa.h
  umad_sm.h
  umad_str.h
  umad_types.h
  )

rdma_library(ibumad libibumad.map
  # See Documentation/versioning.md
  3 3.0.${PACKAGE_VERSION}
  sysfs.c
  umad.c
  umad_str.c
  )

rdma_subst_install(FILES libibumad.udev-rules
  RENAME libibumad.rules
  DESTINATION "${CMAKE_INSTALL_UDEV_RULESDIR}")

