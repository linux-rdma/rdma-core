publish_headers(infiniband
  mad.h
  mad_osd.h
  )

publish_internal_headers(util
  iba_types.h
  )

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # See Documentation/versioning.md
  set(SOVER 5 5.5.${PACKAGE_VERSION})
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  set(SOVER 100 100.5.${PACKAGE_VERSION})
endif()

rdma_library(ibmad libibmad.map
  ${SOVER}
  bm.c
  cc.c
  dump.c
  fields.c
  gs.c
  mad.c
  portid.c
  register.c
  resolve.c
  rpc.c
  sa.c
  serv.c
  smp.c
  vendor.c
  )
target_link_libraries(ibmad LINK_PRIVATE
  ibumad
  )
rdma_pkg_config("ibmad" "libibumad" "")
