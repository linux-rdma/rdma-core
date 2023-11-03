if (ENABLE_LTTNG AND LTTNGUST_FOUND)
  set(TRACE_FILE rxe_trace.c)
endif()

rdma_provider(rxe
  ${TRACE_FILE}
  rxe.c
  )

if (ENABLE_LTTNG AND LTTNGUST_FOUND)
	target_include_directories("rxe-rdmav${IBVERBS_PABI_VERSION}" PUBLIC ".")
	target_link_libraries("rxe-rdmav${IBVERBS_PABI_VERSION}" LINK_PRIVATE LTTng::UST)
endif()
