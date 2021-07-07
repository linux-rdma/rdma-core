# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

rdma_cython_module(pyverbs/providers/mlx5 mlx5
  dr_action.pyx
  dr_domain.pyx
  dr_matcher.pyx
  dr_rule.pyx
  dr_table.pyx
  mlx5_enums.pyx
  mlx5_vfio.pyx
  mlx5dv.pyx
  mlx5dv_crypto.pyx
  mlx5dv_flow.pyx
  mlx5dv_mkey.pyx
  mlx5dv_objects.pyx
  mlx5dv_sched.pyx
)
