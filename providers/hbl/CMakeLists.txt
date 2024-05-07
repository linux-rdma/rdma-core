rdma_shared_provider(hbl libhbl.map
	1 1.0.${PACKAGE_VERSION}
	hbl.c
	verbs.c
)

publish_headers(infiniband
	../../kernel-headers/rdma/hbl_user_ioctl_verbs.h
	hbldv.h
)

SET (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-rpath,'$ORIGIN'")

rdma_pkg_config("hbl" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
