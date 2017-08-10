publish_headers(infiniband
  arch.h
  kern-abi.h
  opcode.h
  sa-kern-abi.h
  sa.h
  verbs.h
  )

publish_internal_headers(infiniband
  driver.h
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
  1 1.1.${PACKAGE_VERSION}
  cmd.c
  compat-1_0.c
  device.c
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
  )
