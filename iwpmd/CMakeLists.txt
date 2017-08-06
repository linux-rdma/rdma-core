rdma_sbin_executable(iwpmd
  iwarp_pm_common.c
  iwarp_pm_helper.c
  iwarp_pm_server.c
  )
target_link_libraries(iwpmd LINK_PRIVATE
  ${SYSTEMD_LIBRARIES}
  ${NL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  )

rdma_man_pages(
  iwpmd.8.in
  iwpmd.conf.5.in
  )

rdma_subst_install(FILES "iwpmd.service.in"
  RENAME "iwpmd.service"
  DESTINATION "${CMAKE_INSTALL_SYSTEMD_SERVICEDIR}")
rdma_subst_install(FILES "iwpmd_init.in"
  DESTINATION "${CMAKE_INSTALL_INITDDIR}"
  RENAME "iwpmd"
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE)
install(FILES "iwpmd.conf" DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")

install(FILES "iwpmd.rules"
  RENAME "90-iwpmd.rules"
  DESTINATION "${CMAKE_INSTALL_UDEV_RULESDIR}")

install(FILES modules-iwpmd.conf
  RENAME "iwpmd.conf"
  DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/rdma/modules")
