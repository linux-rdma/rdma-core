publish_headers(infiniband
  mad.h
  mad_osd.h
  )

publish_internal_headers(util
  iba_types.h
  )

rdma_library(ibmad libibmad.map
  # See Documentation/versioning.md
  5 5.3.${PACKAGE_VERSION}
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
