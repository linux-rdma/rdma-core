# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 HiSilicon Limited. All rights reserved.

rdma_cython_module(pyverbs/providers/hns hns
  hns_enums.pyx
  hnsdv.pyx
)
