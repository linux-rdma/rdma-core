# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

rdma_python_test(tests
  __init__.py
  test_addr.py
  base.py
  test_cq.py
  test_device.py
  test_mr.py
  test_pd.py
  test_qp.py
  utils.py
  )

rdma_python_test(tests
  run_tests.py
  )

rdma_internal_binary(
  run_tests.py
  )
