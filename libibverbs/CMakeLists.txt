publish_headers(infiniband
  arch.h
  opcode.h
  sa-kern-abi.h
  sa.h
  verbs.h
  verbs_api.h
  tm_types.h
  )

publish_internal_headers(infiniband
  cmd_ioctl.h
  cmd_write.h
  driver.h
  kern-abi.h
  marshall.h
  )

if (NOT NL_KIND EQUAL 0)
  set(NEIGH "neigh.c")
else()
  set(NEIGH "")
endif()

configure_file("libibverbs.map.in"
  "${CMAKE_CURRENT_BINARY_DIR}/libibverbs.map" @ONLY)

rdma_library(ibverbs "${CMAKE_CURRENT_BINARY_DIR}/libibverbs.map"
  # See Documentation/versioning.md
  1 1.5.${PACKAGE_VERSION}
  cmd.c
  cmd_counters.c
  cmd_cq.c
  cmd_dm.c
  cmd_fallback.c
  cmd_flow_action.c
  cmd_ioctl.c
  compat-1_0.c
  device.c
  dummy_ops.c
  enum_strs.c
  init.c
  marshall.c
  memory.c
  ${NEIGH}
  sysfs.c
  verbs.c
  )
target_link_libraries(ibverbs LINK_PRIVATE
  ${NL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${CMAKE_DL_LIBS}
  kern-abi
  )
