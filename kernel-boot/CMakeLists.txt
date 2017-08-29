rdma_subst_install(FILES rdma-load-modules@.service.in
  DESTINATION "${CMAKE_INSTALL_SYSTEMD_SERVICEDIR}"
  RENAME rdma-load-modules@.service
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

rdma_subst_install(FILES "rdma-hw.target.in"
  RENAME "rdma-hw.target"
  DESTINATION "${CMAKE_INSTALL_SYSTEMD_SERVICEDIR}"
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(FILES
  modules/infiniband.conf
  modules/iwarp.conf
  modules/opa.conf
  modules/rdma.conf
  modules/roce.conf
  DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/rdma/modules")

install(FILES "rdma-description.rules"
  RENAME "75-rdma-description.rules"
  DESTINATION "${CMAKE_INSTALL_UDEV_RULESDIR}")

install(FILES "rdma-hw-modules.rules"
  RENAME "90-rdma-hw-modules.rules"
  DESTINATION "${CMAKE_INSTALL_UDEV_RULESDIR}")

install(FILES "rdma-ulp-modules.rules"
  RENAME "90-rdma-ulp-modules.rules"
  DESTINATION "${CMAKE_INSTALL_UDEV_RULESDIR}")

install(FILES "rdma-umad.rules"
  RENAME "90-rdma-umad.rules"
  DESTINATION "${CMAKE_INSTALL_UDEV_RULESDIR}")

# This file is intended to be customized by the user, so it is installed in
# /etc/
install(FILES "persistent-ipoib.rules"
  RENAME "70-persistent-ipoib.rules"
  DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/udev/rules.d")
