# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2022-2024 HabanaLabs, Ltd.
# Copyright (C) 2023-2024, Intel Corporation.
# All Rights Reserved.

rdma_cython_module(pyverbs/providers/hbl hbl
  hbl_enums.pyx
  hbldv.pyx
  libhbl.pyx
)
