---
date: 2022-01-12
footer: mlx5
header: "mlx5 Programmer's Manual"
tagline: Verbs
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: mlx5dv_devx_create_eq
---

# NAME

mlx5dv_devx_create_eq - Create an EQ object

mlx5dv_devx_destroy_eq - Destroy an EQ object

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_devx_eq *
mlx5dv_devx_create_eq(struct ibv_context *ibctx, const void *in, size_t inlen,
		      void *out, size_t outlen);

int mlx5dv_devx_destroy_eq(struct mlx5dv_devx_eq *eq);

```

# DESCRIPTION

Create / Destroy an EQ object. Upon creation, the caller prepares the in/out mail boxes based on the device
specification format; For the input mailbox, caller needs to prepare all fields except "eqc.log_page_size"
and the pas list, which will be set by the driver. The "eqc.intr" field should be used from the output of
mlx5dv_devx_alloc_msi_vector().

# ARGUMENTS
*ibctx*
:	RDMA device context to create the action on.

*in*
:	A buffer which contains the command's input data provided in a device specification format.

*inlen*
:	The size of *in* buffer in bytes.

*out*
:	A buffer which contains the command's output data according to the device specification format.

*outlen*
:	The size of *out* buffer in bytes.

*eq*
:	The  EQ object to work on.

```c
struct mlx5dv_devx_eq {
    void *vaddr;
};
```

*vaddr*
:	EQ VA that was allocated in the driver for.

# NOTES

mlx5dv_devx_query_eqn() will not support vectors which are used by mlx5dv_devx_create_eq().

# RETURN VALUE

Upon success *mlx5dv_devx_create_eq* will return a new *struct mlx5dv_devx_eq*;
On error NULL will be returned and errno will be set.

Upon success *mlx5dv_devx_destroy_eq* will return 0, on error errno will be returned.

If the error value is EREMOTEIO, outbox.status and outbox.syndrome will contain the command failure details.

# SEE ALSO

*mlx5dv_devx_alloc_msi_vector(3)*, *mlx5dv_devx_query_eqn(3)*

# AUTHOR

Mark Zhang <markzhang@nvidia.com>
