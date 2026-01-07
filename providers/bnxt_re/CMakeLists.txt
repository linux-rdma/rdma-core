rdma_shared_provider(bnxt_re bnxt_re.map
	1 1.1.${PACKAGE_VERSION}
	db.c
	main.c
	memory.c
	verbs.c
	dv.c
)

publish_headers(infiniband
  bnxt_re_dv.h
)

rdma_pkg_config("bnxt_re" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")

if (ENABLE_LTTNG AND LTTNGUST_FOUND)
  target_include_directories(bnxt_re PUBLIC ".")
  target_link_libraries(bnxt_re LINK_PRIVATE LTTng::UST)
endif()
