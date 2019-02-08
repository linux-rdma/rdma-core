publish_internal_headers(""
  ../include/ibdiag_common.h
  ../include/ibdiag_sa.h
  )

add_library(ibdiags_tools STATIC
  ibdiag_common.c
  ibdiag_sa.c
  )
target_include_directories(ibdiags_tools PRIVATE "/usr/include/infiniband")

function(ibdiag_programs)
  foreach(I ${ARGN})
    rdma_sbin_executable(${I} "${I}.c")
    target_link_libraries(${I} PRIVATE ${RT_LIBRARIES} ibumad ibmad ibdiags_tools ibnetdisc osmcomp)
    target_include_directories(${I} PRIVATE "/usr/include/infiniband")
  endforeach()
endfunction()

ibdiag_programs(
  dump_fts
  ibaddr
  ibcacheedit
  ibccconfig
  ibccquery
  iblinkinfo
  ibnetdiscover
  ibping
  ibportstate
  ibqueryerrors
  ibroute
  ibstat
  ibsysstat
  ibtracert
  perfquery
  saquery
  sminfo
  smpdump
  smpquery
  vendstat
  )

rdma_test_executable(ibsendtrap "ibsendtrap.c")
target_link_libraries(ibsendtrap PRIVATE ibumad ibmad ibdiags_tools)
target_include_directories(ibsendtrap PRIVATE "/usr/include/infiniband")
rdma_test_executable(mcm_rereg_test "mcm_rereg_test.c")
target_link_libraries(mcm_rereg_test PRIVATE ibumad ibmad ibdiags_tools)
target_include_directories(mcm_rereg_test PRIVATE "/usr/include/infiniband")
