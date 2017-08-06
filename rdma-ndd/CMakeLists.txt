# COPYRIGHT (c) 2016 Intel Corporation.
# Licensed under BSD (MIT variant) or GPLv2. See COPYING.

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

rdma_sbin_executable(rdma-ndd
  rdma-ndd.c
  )

target_link_libraries(rdma-ndd LINK_PRIVATE
  ${SYSTEMD_LIBRARIES}
  ${UDEV_LIBRARIES}
  )

# FIXME Autogenerate from the .rst
rdma_man_pages(
  rdma-ndd.8.in
  )

install(FILES "rdma-ndd.rules"
  RENAME "60-rdma-ndd.rules"
  DESTINATION "${CMAKE_INSTALL_UDEV_RULESDIR}")

rdma_subst_install(FILES "rdma-ndd.service.in"
  DESTINATION "${CMAKE_INSTALL_SYSTEMD_SERVICEDIR}"
  RENAME "rdma-ndd.service")

