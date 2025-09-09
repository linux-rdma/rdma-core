rdma_shared_provider(ionic libionic.map
	1 1.0.${PACKAGE_VERSION}
	ionic.c
	ionic_verbs.c
	ionic_memory.c
	ionic_queue.c
	ionic_dv.c
)

publish_headers(infiniband
	ionic_dv.h
)

rdma_pkg_config("ionic" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
