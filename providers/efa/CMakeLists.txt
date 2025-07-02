if (ENABLE_LTTNG AND LTTNGUST_FOUND)
  rdma_provider(efa_trace
    efa_trace.c
  )
endif()

rdma_shared_provider(efa libefa.map
	1 1.3.${PACKAGE_VERSION}
	efa.c
	verbs.c
)

publish_headers(infiniband
	efadv.h
)

rdma_pkg_config("efa" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")

if (ENABLE_LTTNG AND LTTNGUST_FOUND)
	target_link_libraries(efa LINK_PRIVATE LTTng::UST)
	target_include_directories(efa_trace-rdmav${IBVERBS_PABI_VERSION} PUBLIC ".")
	target_link_libraries(efa_trace-rdmav${IBVERBS_PABI_VERSION} LINK_PRIVATE LTTng::UST)
	if (ENABLE_STATIC)
		target_link_libraries(efa-static LINK_PRIVATE LTTng::UST)
		target_include_directories(efa_trace PUBLIC ".")
		target_link_libraries(efa_trace LINK_PRIVATE LTTng::UST)
	endif()
endif()
