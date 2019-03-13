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
  )

rdma_python_module(pyverbs
  __init__.py
  pyverbs_error.py
  run_tests.py
  utils.py
  )

rdma_python_module(pyverbs/tests
  tests/__init__.py
  tests/addr.py
  tests/base.py
  tests/cq.py
  tests/device.py
  tests/mr.py
  tests/pd.py
  tests/qp.py
  tests/utils.py
  )

rdma_internal_binary(
  run_tests.py
  )
