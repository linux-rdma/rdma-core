publish_internal_headers(""
  ibdiag_common.h
  ibdiag_sa.h
  )

install(FILES
  etc/error_thresholds
  etc/ibdiag.conf
  DESTINATION "${IBDIAG_CONFIG_PATH}")

add_library(ibdiags_tools STATIC
  ibdiag_common.c
  ibdiag_sa.c
  )

function(ibdiag_programs)
  foreach(I ${ARGN})
    rdma_sbin_executable(${I} "${I}.c")
    target_link_libraries(${I} LINK_PRIVATE ${RT_LIBRARIES} ibumad ibmad ibdiags_tools ibnetdisc)
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
target_link_libraries(ibsendtrap LINK_PRIVATE ibumad ibmad ibdiags_tools)
rdma_test_executable(mcm_rereg_test "mcm_rereg_test.c")
target_link_libraries(mcm_rereg_test LINK_PRIVATE ibumad ibmad ibdiags_tools)
