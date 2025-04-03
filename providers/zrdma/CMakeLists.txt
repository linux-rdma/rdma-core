set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
rdma_shared_provider(zrdma libzrdma.map
	1 1.1.${PACKAGE_VERSION}
  zxdh_zrdma.c
  zxdh_verbs.c
)

rdma_pkg_config("zrdma" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
