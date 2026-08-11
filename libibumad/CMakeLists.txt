publish_headers(infiniband
  umad.h
  umad_cm.h
  umad_sa.h
  umad_sa_mcm.h
  umad_sm.h
  umad_str.h
  umad_types.h
  )

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # See Documentation/versioning.md
  set(SOVER 3 3.4.${PACKAGE_VERSION})
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  set(SOVER 100 100.4.${PACKAGE_VERSION})
endif()

rdma_library(ibumad libibumad.map
  ${SOVER}
  sysfs.c
  umad.c
  umad_str.c
  )

rdma_pkg_config("ibumad" "" "")
