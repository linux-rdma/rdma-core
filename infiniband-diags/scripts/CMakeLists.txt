function(_rdma_sbin_interp INTERP IFN OFN)
  configure_file("${IFN}" "${CMAKE_CURRENT_BINARY_DIR}/${OFN}" @ONLY)
  file(WRITE "${BUILD_BIN}/${OFN}" "#!${INTERP}\nexec ${INTERP} ${CMAKE_CURRENT_BINARY_DIR}/${OFN} \"$@\"\n")
  execute_process(COMMAND "chmod" "a+x" "${BUILD_BIN}/${OFN}")

  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${OFN}"
    DESTINATION "${CMAKE_INSTALL_SBINDIR}"
    PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE)
endfunction()

function(_rdma_sbin_interp_link INTERP IFN OFN)
  file(WRITE "${BUILD_BIN}/${OFN}" "#!${INTERP}\nexec ${INTERP} ${CMAKE_CURRENT_SOURCE_DIR}/${IFN} \"$@\"\n")
  execute_process(COMMAND "chmod" "a+x" "${BUILD_BIN}/${OFN}")

  install(FILES "${IFN}"
    DESTINATION "${CMAKE_INSTALL_SBINDIR}"
    RENAME "${OFN}"
    PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE)
endfunction()

function(rdma_sbin_shell_program)
  foreach(IFN ${ARGN})
    if (IFN MATCHES "\\.sh\\.in")
      if (DISTRO_FLAVOUR STREQUAL Debian)
	string(REGEX REPLACE "^(.+)\\.sh\\.in$" "\\1" OFN "${IFN}")
      else()
	string(REGEX REPLACE "^(.+)\\.in$" "\\1" OFN "${IFN}")
      endif()
      _rdma_sbin_interp("/bin/bash" "${IFN}" "${OFN}")
    elseif (IFN MATCHES "\\.in")
      string(REGEX REPLACE "^(.+)\\.in$" "\\1" OFN "${IFN}")
      _rdma_sbin_interp("/bin/bash" "${IFN}" "${OFN}")
    elseif (IFN MATCHES "\\.sh")
      if (DISTRO_FLAVOUR STREQUAL Debian)
	string(REGEX REPLACE "^(.+)\\.sh$" "\\1" OFN "${IFN}")
      else()
	set(OFN "${IFN}")
      endif()
      _rdma_sbin_interp_link("/bin/bash" "${IFN}" "${OFN}")
    else()
      _rdma_sbin_interp_link("/bin/bash" "${IFN}" "${IFN}")
    endif()
  endforeach()
endfunction()

function(rdma_sbin_perl_program)
  foreach(IFN ${ARGN})
    if (IFN MATCHES "\\.pl\\.in")
      if (DISTRO_FLAVOUR STREQUAL Debian)
	string(REGEX REPLACE "^(.+)\\.pl\\.in$" "\\1" OFN "${IFN}")
      else()
	string(REGEX REPLACE "^(.+)\\.in$" "\\1" OFN "${IFN}")
      endif()
      _rdma_sbin_interp("/usr/bin/perl" "${IFN}" "${OFN}")
    elseif (IFN MATCHES "\\.pl")
      if (DISTRO_FLAVOUR STREQUAL Debian)
	string(REGEX REPLACE "^(.+)\\.pl$" "\\1" OFN "${IFN}")
      else()
	set(OFN "${IFN}")
      endif()
      _rdma_sbin_interp_link("/usr/bin/perl" "${IFN}" "${OFN}")
    endif()
  endforeach()
endfunction()

set(IBSCRIPTPATH "${CMAKE_INSTALL_FULL_SBINDIR}")

rdma_sbin_shell_program(
  dump_lfts.sh.in
  dump_mfts.sh.in
  ibhosts.in
  ibnodes.in
  ibrouters.in
  ibstatus
  ibswitches.in
  )

rdma_sbin_perl_program(
  check_lft_balance.pl
  ibfindnodesusing.pl
  ibidsverify.pl
  )

install(FILES "IBswcountlimits.pm"
  DESTINATION "${CMAKE_INSTALL_PERLDIR}")

if (ENABLE_IBDIAGS_COMPAT)
  rdma_sbin_shell_program(
    ibcheckerrors.in
    ibcheckerrs.in
    ibchecknet.in
    ibchecknode.in
    ibcheckport.in
    ibcheckportstate.in
    ibcheckportwidth.in
    ibcheckstate.in
    ibcheckwidth.in
    ibclearcounters.in
    ibclearerrors.in
    ibdatacounters.in
    ibdatacounts.in
    set_nodedesc.sh
    )

  rdma_sbin_perl_program(
    ibdiscover.pl
    iblinkinfo.pl.in
    ibprintca.pl
    ibprintrt.pl
    ibprintswitch.pl
    ibqueryerrors.pl.in
    ibswportwatch.pl
    )
endif()
