publish_headers(infiniband
  ../include/infiniband/ibnetdisc.h
  ../include/infiniband/ibnetdisc_osd.h
  )

rdma_library(ibnetdisc libibnetdisc.map
  # See Documentation/versioning.md
  5 5.0.${PACKAGE_VERSION}
  chassis.c
  ibnetdisc.c
  ibnetdisc_cache.c
  query_smp.c
  )
target_link_libraries(ibnetdisc LINK_PRIVATE
  ibmad
  ibumad
  osmcomp
  )
# FIXME for osmcomp
target_include_directories(ibnetdisc PRIVATE "/usr/include/infiniband")
rdma_pkg_config("ibnetdisc" "libibumad libibmad" "")

rdma_test_executable(testleaks ../test/testleaks.c)
target_link_libraries(testleaks LINK_PRIVATE
  ibmad
  ibnetdisc
)
target_include_directories(testleaks PRIVATE "/usr/include/infiniband")
