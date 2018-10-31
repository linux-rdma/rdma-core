# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

rdma_cython_module(pyverbs
  enums.pyx
  base.pyx
  device.pyx
  addr.pyx
  )

rdma_python_module(pyverbs
  pyverbs_error.py
  __init__.py
  run_tests.py
  )

rdma_python_test(pyverbs/tests
  tests/__init__.py
  tests/device.py
  )

rdma_internal_binary(
  run_tests.py
  )
