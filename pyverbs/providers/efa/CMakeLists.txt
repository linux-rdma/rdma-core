# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.

rdma_cython_module(pyverbs/providers/efa efa
  efa_enums.pyx
  efadv.pyx
)
