# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

rdma_cython_module(pyverbs/providers/mlx5 mlx5
  mlx5dv.pyx
  mlx5_enums.pyx
)
