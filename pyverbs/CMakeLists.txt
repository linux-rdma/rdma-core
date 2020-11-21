# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file
# Copyright (c) 2020, Intel Corporation. All rights reserved. See COPYING file

publish_internal_headers(""
  dmabuf_alloc.h
)

rdma_cython_module(pyverbs ""
  addr.pyx
  base.pyx
  cm_enums.pyx
  cmid.pyx
  cq.pyx
  device.pyx
  dmabuf.pyx
  dmabuf_alloc.c
  enums.pyx
  mem_alloc.pyx
  mr.pyx
  pd.pyx
  qp.pyx
  srq.pyx
  wr.pyx
  xrcd.pyx
)

rdma_python_module(pyverbs
  __init__.py
  pyverbs_error.py
  utils.py
  )

# mlx5 and efa providers are not built without coherent DMA, e.g. ARM32 build.
if (HAVE_COHERENT_DMA)
add_subdirectory(providers/mlx5)
add_subdirectory(providers/efa)
endif()
