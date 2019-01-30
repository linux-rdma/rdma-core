set(MLX5_DEBUG "FALSE" CACHE BOOL
  "Enable expensive runtime logging options for the mlx5 verbs provider")
if (MLX5_DEBUG)
  add_definitions("-DMLX5_DEBUG")
endif()

set(MLX5_MW_DEBUG "FALSE" CACHE BOOL
  "Enable extra validation of memory windows for the mlx5 verbs provider")
if (MLX5_MW_DEBUG)
  add_definitions("-DMW_DEBUG")
endif()

rdma_shared_provider(mlx5 libmlx5.map
  1 1.9.${PACKAGE_VERSION}
  buf.c
  cq.c
  dbrec.c
  mlx5.c
  qp.c
  srq.c
  verbs.c
)

publish_headers(infiniband
  ../../kernel-headers/rdma/mlx5_user_ioctl_verbs.h
  mlx5_api.h
  mlx5dv.h
)

rdma_pkg_config("mlx5" "libibverbs" "${CMAKE_THREAD_LIBS_INIT}")
