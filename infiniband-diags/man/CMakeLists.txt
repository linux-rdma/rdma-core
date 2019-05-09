# rst2man has no way to set the include search path and we need to substitute
# into the common files, so subst/link them all into the build directory
function(rdma_rst_common)
  foreach(I ${ARGN})
    if ("${I}" MATCHES "\\.in.rst$")
      string(REGEX REPLACE "^(.+)\\.in.rst$" "\\1" BASE_NAME "${I}")
      configure_file("common/${I}" "${CMAKE_CURRENT_BINARY_DIR}/common/${BASE_NAME}.rst" @ONLY)
    else()
      if (NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_CURRENT_BINARY_DIR)
	rdma_create_symlink("${CMAKE_CURRENT_SOURCE_DIR}/common/${I}" "${CMAKE_CURRENT_BINARY_DIR}/common/${I}")
      endif()
    endif()
  endforeach()
endfunction()

rdma_rst_common(
  opt_cache.rst
  opt_C.rst
  opt_diffcheck.rst
  opt_diff.rst
  opt_d.rst
  opt_D.rst
  opt_D_with_param.rst
  opt_e.rst
  opt_G.rst
  opt_G_with_param.rst
  opt_h.rst
  opt_K.rst
  opt_load-cache.rst
  opt_L.rst
  opt_node_name_map.rst
  opt_o-outstanding_smps.rst
  opt_ports-file.rst
  opt_P.rst
  opt_s.rst
  opt_t.rst
  opt_v.rst
  opt_V.rst
  opt_y.rst
  opt_z-config.in.rst
  sec_config-file.in.rst
  sec_node-name-map.rst
  sec_portselection.rst
  sec_ports-file.rst
  sec_topology-file.rst
)

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
