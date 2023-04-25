# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file
# Copyright (c) 2020, Intel Corporation. All rights reserved. See COPYING file
# Copyright 2023 Amazon.com, Inc. or its affiliates. All rights reserved.

publish_internal_headers(""
  drm_dmabuf_alloc.h
  habana_dmabuf_alloc.h
)

if (DRM_INCLUDE_DIRS)
  set(DRM_DMABUF_ALLOC drm_dmabuf_alloc.c)
else()
  set(DRM_DMABUF_ALLOC drm_dmabuf_alloc_stub.c)
endif()

if (HABANA_INCLUDE_DIR)
  set(HABANA_DMABUF_ALLOC habana_dmabuf_alloc.c)
else()
  set(HABANA_DMABUF_ALLOC habana_dmabuf_alloc_stub.c)
endif()

if (HAVE_COHERENT_DMA)
  set(DMA_UTIL dma_util.pyx)
else()
  set(DMA_UTIL "")
endif()

rdma_cython_module(pyverbs "${DMABUF_LINKER_FLAGS}"
  dmabuf.pyx
  ${DRM_DMABUF_ALLOC}
  ${HABANA_DMABUF_ALLOC}
)

rdma_cython_module(pyverbs ""
  addr.pyx
  base.pyx
  cm_enums.pyx
  cmid.pyx
  cq.pyx
  device.pyx
  ${DMA_UTIL}
  enums.pyx
  flow.pyx
  fork.pyx
  mem_alloc.pyx
  mr.pyx
  pd.pyx
  qp.pyx
  spec.pyx
  srq.pyx
  wq.pyx
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
