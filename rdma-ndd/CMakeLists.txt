# COPYRIGHT (c) 2016 Intel Corporation. See COPYING file

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NO_STRICT_ALIASING_FLAGS}")

install(FILES rdma-ndd.conf DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")

rdma_sbin_executable(rdma-ndd
  rdma-ndd.c
  )

target_link_libraries(rdma-ndd LINK_PRIVATE ${UDEV_LIBRARIES})

rdma_man_pages(
  doc/man/rdma-ndd.8.in
  )

rdma_subst_install(FILES "rdma-ndd.service.in"
  DESTINATION "${CMAKE_INSTALL_SYSTEMD_SERVICEDIR}"
  RENAME "rdma-ndd.service")

