if (ENABLE_LTTNG AND LTTNGUST_FOUND)
  set(TRACE_FILE efa_trace.c)
endif()

rdma_shared_provider(efa libefa.map
	1 1.2.${PACKAGE_VERSION}
	${TRACE_FILE}
	efa.c
	verbs.c
)

publish_headers(infiniband
	efadv.h
)

rdma_pkg_config("efa" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")

if (ENABLE_LTTNG AND LTTNGUST_FOUND)
	target_include_directories(efa PUBLIC ".")
	target_link_libraries(efa LINK_PRIVATE LTTng::UST)
endif()
