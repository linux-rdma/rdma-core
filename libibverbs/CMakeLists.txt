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

configure_file("libibverbs.map.in"
  "${CMAKE_CURRENT_BINARY_DIR}/libibverbs.map" @ONLY)

rdma_library(ibverbs "${CMAKE_CURRENT_BINARY_DIR}/libibverbs.map"
  # See Documentation/versioning.md
  1 1.8.${PACKAGE_VERSION}
  all_providers.c
  cmd.c
  cmd_ah.c
  cmd_counters.c
  cmd_cq.c
  cmd_device.c
  cmd_dm.c
  cmd_fallback.c
  cmd_flow.c
  cmd_flow_action.c
  cmd_ioctl.c
  cmd_mr.c
  cmd_mw.c
  cmd_pd.c
  cmd_rwq_ind.c
  cmd_xrcd.c
  compat-1_0.c
  device.c
  dummy_ops.c
  dynamic_driver.c
  enum_strs.c
  ibdev_nl.c
  init.c
  marshall.c
  memory.c
  neigh.c
  static_driver.c
  sysfs.c
  verbs.c
  )
target_link_libraries(ibverbs LINK_PRIVATE
  ${NL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${CMAKE_DL_LIBS}
  kern-abi
  )

function(ibverbs_finalize)
  if (ENABLE_STATIC)
    # In static mode the .pc file lists all of the providers for static
    # linking. The user should set RDMA_STATIC_PROVIDERS to select which ones
    # to include.
    list(LENGTH RDMA_PROVIDER_LIST LEN)
    math(EXPR LEN ${LEN}-1)
    foreach(I RANGE 0 ${LEN} 2)
      list(GET RDMA_PROVIDER_LIST ${I} PROVIDER_NAME)
      math(EXPR I ${I}+1)
      list(GET RDMA_PROVIDER_LIST ${I} LIB_NAME)
      math(EXPR I ${I}+1)

      set(PROVIDER_LIBS "${PROVIDER_LIBS} -l${LIB_NAME}")
      set(FOR_EACH_PROVIDER "${FOR_EACH_PROVIDER} FOR_PROVIDER(${PROVIDER_NAME})")
    endforeach()

    if (NOT NL_KIND EQUAL 0)
      set(REQUIRES "libnl-3.0, libnl-route-3.0")
    endif()
    rdma_pkg_config("ibverbs" "${REQUIRES}" "${PROVIDER_LIBS} -libverbs ${CMAKE_THREAD_LIBS_INIT}")

    file(WRITE ${BUILD_INCLUDE}/infiniband/all_providers.h "#define FOR_EACH_PROVIDER() ${FOR_EACH_PROVIDER}")
  else()
    rdma_pkg_config("ibverbs" "" "${CMAKE_THREAD_LIBS_INIT}")
  endif()
endfunction()
