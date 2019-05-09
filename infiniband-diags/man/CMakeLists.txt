set(BUILD_DATE "2019")

# rst2man has no way to set the include search path
rdma_create_symlink("${CMAKE_CURRENT_SOURCE_DIR}/common" "${CMAKE_CURRENT_BINARY_DIR}/common")

rdma_man_pages(
  check_lft_balance.8.in.rst
  dump_fts.8.in.rst
  ibaddr.8.in.rst
  ibcacheedit.8.in.rst
  ibccconfig.8.in.rst
  ibccquery.8.in.rst
  ibfindnodesusing.8.in.rst
  ibhosts.8.in.rst
  ibidsverify.8.in.rst
  iblinkinfo.8.in.rst
  ibnetdiscover.8.in.rst
  ibnodes.8.in.rst
  ibping.8.in.rst
  ibportstate.8.in.rst
  ibqueryerrors.8.in.rst
  ibroute.8.in.rst
  ibrouters.8.in.rst
  ibstat.8.in.rst
  ibstatus.8.in.rst
  ibswitches.8.in.rst
  ibsysstat.8.in.rst
  ibtracert.8.in.rst
  infiniband-diags.8.in.rst
  perfquery.8.in.rst
  saquery.8.in.rst
  sminfo.8.in.rst
  smpdump.8.in.rst
  smpquery.8.in.rst
  vendstat.8.in.rst
  )

rdma_alias_man_pages(
  dump_fts.8 dump_lfts.8
  dump_fts.8 dump_mfts.8
  )

if (ENABLE_IBDIAGS_COMPAT)
  rdma_man_pages(
    ibcheckerrors.8
    ibcheckerrs.8
    ibchecknet.8
    ibchecknode.8
    ibcheckport.8
    ibcheckportstate.8
    ibcheckportwidth.8
    ibcheckstate.8
    ibcheckwidth.8
    ibclearcounters.8
    ibclearerrors.8
    ibdatacounters.8
    ibdatacounts.8
    ibdiscover.8
    ibprintca.8
    ibprintrt.8
    ibprintswitch.8
    ibswportwatch.8
    )
endif()
