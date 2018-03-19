publish_internal_headers(rdma
  rdma/bnxt_re-abi.h
  rdma/cxgb3-abi.h
  rdma/cxgb4-abi.h
  rdma/hns-abi.h
  rdma/i40iw-abi.h
  rdma/ib_user_cm.h
  rdma/ib_user_ioctl_verbs.h
  rdma/ib_user_mad.h
  rdma/ib_user_sa.h
  rdma/ib_user_verbs.h
  rdma/mlx4-abi.h
  rdma/mlx5-abi.h
  rdma/mthca-abi.h
  rdma/nes-abi.h
  rdma/ocrdma-abi.h
  rdma/qedr-abi.h
  rdma/rdma_netlink.h
  rdma/rdma_user_cm.h
  rdma/rdma_user_ioctl.h
  rdma/rdma_user_rxe.h
  rdma/vmw_pvrdma-abi.h
  )

publish_internal_headers(rdma/hfi
  rdma/hfi/hfi1_ioctl.h
  rdma/hfi/hfi1_user.h
  )

function(rdma_kernel_provider_abi)
  # Older versions of cmake do not create the output directory automatically
  set(DDIR "${BUILD_INCLUDE}/kernel-abi")
  if(NOT EXISTS "${DDIR}/")
    execute_process(COMMAND "${CMAKE_COMMAND}" "-E" "make_directory"
      "${DDIR}" RESULT_VARIABLE retcode)
    if(NOT "${retcode}" STREQUAL "0")
      message(FATAL_ERROR "Failed to create directory ${DDIR}")
    endif()
  endif()

  set(HDRS "")
  foreach(IHDR ${ARGN})
    get_filename_component(FIL ${IHDR} NAME)
    set(OHDR "${DDIR}/${FIL}")
    set(HDRS ${HDRS} ${OHDR})
    add_custom_command(
      OUTPUT "${OHDR}"
      COMMAND "${PYTHON_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/buildlib/make_abi_structs.py" "${IHDR}" "${OHDR}"
      MAIN_DEPENDENCY "${IHDR}"
      DEPENDS "${CMAKE_SOURCE_DIR}/buildlib/make_abi_structs.py"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      COMMENT "Creating ABI wrapper ${OHDR}"
      )
  endforeach()

  # This weird construction is needed to ensure ordering of the build.
  add_library(kern-abi STATIC kern-abi.c ${HDRS})
endfunction()

# Transform the kernel ABIs used by the providers
rdma_kernel_provider_abi(
  rdma/ib_user_verbs.h
  )
