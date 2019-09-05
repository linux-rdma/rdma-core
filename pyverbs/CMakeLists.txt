# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

rdma_cython_module(pyverbs
  addr.pyx
  base.pyx
  cq.pyx
  device.pyx
  enums.pyx
  mr.pyx
  pd.pyx
  qp.pyx
  wr.pyx
  xrcd.pyx
  )

rdma_python_module(pyverbs
  __init__.py
  pyverbs_error.py
  utils.py
  )
