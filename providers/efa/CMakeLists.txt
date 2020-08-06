rdma_shared_provider(efa libefa.map
	1 1.1.${PACKAGE_VERSION}
	efa.c
	verbs.c
)

publish_headers(infiniband
	efadv.h
)

rdma_pkg_config("efa" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
