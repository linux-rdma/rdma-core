rdma_executable(iwpmd
  iwarp_pm_common.c
  iwarp_pm_helper.c
  iwarp_pm_server.c
  )
target_link_libraries(iwpmd
  ${NL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  )
# FIXME iwpmd_init init.d file
# FIXME iwpmd.service systemd file
# FIXME iwpmd.conf
