if (ENABLE_LTTNG AND LTTNGUST_FOUND)
  rdma_provider(rxe_trace
    rxe_trace.c
    )
endif()

rdma_provider(rxe
  rxe.c
  )

if (ENABLE_LTTNG AND LTTNGUST_FOUND)
	target_link_libraries("rxe-rdmav${IBVERBS_PABI_VERSION}" LINK_PRIVATE LTTng::UST)
	target_include_directories("rxe_trace-rdmav${IBVERBS_PABI_VERSION}" PUBLIC ".")
	target_link_libraries("rxe_trace-rdmav${IBVERBS_PABI_VERSION}" LINK_PRIVATE LTTng::UST)
	if (ENABLE_STATIC)
		target_link_libraries(rxe LINK_PRIVATE LTTng::UST)
		target_include_directories("rxe_trace" PUBLIC ".")
		target_link_libraries("rxe_trace" LINK_PRIVATE LTTng::UST)
	endif()
endif()
