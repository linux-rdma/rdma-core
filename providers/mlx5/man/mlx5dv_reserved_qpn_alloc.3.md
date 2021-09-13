---
layout: page
title: mlx5dv_reserved_qpn_alloc / dealloc
section: 3
tagline: Verbs
date: 2020-12-29
header: "mlx5 Programmer's Manual"
footer: mlx5
---

# NAME

mlx5dv_reserved_qpn_alloc - Allocate a reserved QP number from device

mlx5dv_reserved_qpn_dealloc - Release the reserved QP number

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_reserved_qpn_alloc(struct ibv_context *ctx, uint32_t *qpn);

int mlx5dv_reserved_qpn_dealloc(struct ibv_context *ctx, uint32_t qpn);
```

# DESCRIPTION

When work with RDMA_CM RDMA_TCP_PS + external QP support, a client node needs GUID level unique QP numbers to comply with the CM's timewait logic.

If a real unique QP is not allocated, a device global QPN value is required and can be allocated via this interface.

The mlx5 DCI QP is such an example, which could connect to the remote DCT's multiple times as long as the application provides unique QPN for each new RDMA_CM connection.

These 2 APIs provide the allocation/deallocation of a unique QP number from/to device. This qpn can be used with
DC QPN in RDMA_CM connection establishment, which will comply with the CM timewait kernel logic.

# ARGUMENTS

*ctx*
:	The device context to issue the action on.

*qpn*
:	The allocated QP number (for alloc API), or the QP number to be deallocated (for dealloc API).

# RETURN VALUE

0 on success; EOPNOTSUPP if not supported, or other errno value on other failures.

# AUTHOR

Mark Zhang <markzhang@nvidia.com>

Alex Rosenbaum <alexr@nvidia.com>
