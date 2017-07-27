rdma_executable(iwpmd
  iwarp_pm_common.c
  iwarp_pm_helper.c
  iwarp_pm_server.c
  )
target_link_libraries(iwpmd LINK_PRIVATE
  ${NL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  )

rdma_man_pages(
  iwpmd.8.in
  iwpmd.conf.5.in
  )

install(FILES "iwpmd.service" DESTINATION "${CMAKE_INSTALL_SYSTEMD_SERVICEDIR}")
install(FILES "iwpmd_init"
  DESTINATION "${CMAKE_INSTALL_INITDDIR}"
  RENAME "iwpmd"
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE)
install(FILES "iwpmd.conf" DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")
