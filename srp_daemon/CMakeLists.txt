set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NO_STRICT_ALIASING_FLAGS}")

rdma_man_pages(
  ibsrpdm.8
  srp_daemon.8.in
  srp_daemon.service.5
  srp_daemon_port@.service.5
  )

rdma_sbin_executable(srp_daemon
  srp_daemon.c
  srp_handle_traps.c
  srp_sync.c
  )
target_link_libraries(srp_daemon LINK_PRIVATE
  ibverbs
  ibumad
  ${RT_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  )

rdma_install_symlink(srp_daemon "${CMAKE_INSTALL_SBINDIR}/ibsrpdm")
# FIXME: Why?
rdma_install_symlink(srp_daemon "${CMAKE_INSTALL_SBINDIR}/run_srp_daemon")
rdma_subst_install(FILES "srp_daemon.sh.in"
  DESTINATION "${CMAKE_INSTALL_SBINDIR}"
  RENAME "srp_daemon.sh"
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE)

install(FILES start_on_all_ports
  DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/srp_daemon"
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE)

rdma_subst_install(FILES srp_daemon.service.in
  DESTINATION "${CMAKE_INSTALL_SYSTEMD_SERVICEDIR}"
  RENAME srp_daemon.service
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

rdma_subst_install(FILES srp_daemon_port@.service.in
  DESTINATION "${CMAKE_INSTALL_SYSTEMD_SERVICEDIR}"
  RENAME srp_daemon_port@.service
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(FILES srp_daemon.conf DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")

install(FILES "srp_daemon.rules"
  RENAME "60-srp_daemon.rules"
  DESTINATION "${CMAKE_INSTALL_UDEV_RULESDIR}")

install(FILES modules-srp_daemon.conf
  RENAME "srp_daemon.conf"
  DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/rdma/modules")

# FIXME: The ib init.d file should really be included in rdma-core as well.
set(RDMA_SERVICE "openibd" CACHE STRING "init.d file service name to order srpd after")
# NOTE: These defaults are for CentOS, packagers should override.
set(SRP_DEFAULT_START "2 3 4 5" CACHE STRING "Default-Start service data for srpd")
set(SRP_DEFAULT_STOP "0 1 6" CACHE STRING "Default-Stop service data for srpd")
configure_file(srpd.in "${CMAKE_CURRENT_BINARY_DIR}/srpd")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/srpd"
  DESTINATION "${CMAKE_INSTALL_INITDDIR}"
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE)
