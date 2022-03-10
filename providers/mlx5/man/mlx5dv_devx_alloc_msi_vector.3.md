---
date: 2022-01-12
footer: mlx5
header: "mlx5 Programmer's Manual"
tagline: Verbs
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: mlx5dv_devx_alloc_msi_vector
---

# NAME

mlx5dv_devx_alloc_msi_vector - Allocate an msi vector to be used for creating an EQ.

mlx5dv_devx_free_msi_vector - Release an msi vector.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_devx_msi_vector *
mlx5dv_devx_alloc_msi_vector(struct ibv_context *ibctx);

int mlx5dv_devx_free_msi_vector(struct mlx5dv_devx_msi_vector *msi);

```

# DESCRIPTION

Allocate or free an msi vector to be used for creating an EQ.

The allocate API exposes a mlx5dv_devx_msi_vector object, which includes an msi vector and a fd. The vector
can be used as the "eqc.intr" field when creating an EQ, while the fd (created as non-blocking) can be polled
to see once there is some data on that EQ.

# ARGUMENTS
*ibctx*
:	RDMA device context to create the action on.

*msi*
:	The msi vector object to work on.

## msi_vector

```c
struct mlx5dv_devx_msi_vector {
	int vector;
	int fd;
};
```
*vector*
:	The vector to be used when creating the EQ over the device specification.

*fd*
:	The FD that will be used for polling.

# RETURN VALUE

Upon success *mlx5dv_devx_alloc_msi_vector* will return a new *struct mlx5dv_devx_msi_vector*;
On error NULL will be returned and errno will be set.

Upon success *mlx5dv_devx_free_msi_vector* will return 0, on error errno will be returned.

# AUTHOR

Mark Zhang <markzhang@nvidia.com>
