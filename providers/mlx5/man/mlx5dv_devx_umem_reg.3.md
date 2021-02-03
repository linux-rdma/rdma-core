---
layout: page
title: mlx5dv_devx_umem_reg, mlx5dv_devx_umem_dereg
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_umem_reg - Register a user memory to be used by the devx interface

mlx5dv_devx_umem_reg_ex - Register a user memory to be used by the devx interface

mlx5dv_devx_umem_dereg - Deregister a devx umem object

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_devx_umem {
	uint32_t umem_id;
};

struct mlx5dv_devx_umem *
mlx5dv_devx_umem_reg(struct ibv_context *context, void *addr, size_t size,
		     uint32_t access)

struct mlx5dv_devx_umem_in {
	void *addr;
	size_t size;
	uint32_t access;
	uint64_t pgsz_bitmap;
	uint64_t comp_mask;
};

struct mlx5dv_devx_umem *
mlx5dv_devx_umem_reg_ex(struct ibv_context *ctx, struct mlx5dv_devx_umem_in *umem_in);

int mlx5dv_devx_umem_dereg(struct mlx5dv_devx_umem *dv_devx_umem)
```

# DESCRIPTION

Register or deregister a user memory to be used by the devx interface.

The register verb exposes a UMEM DEVX object for user memory registration for
DMA.  The API to register the user memory gets as input the user address,
length and access flags, and provides to the user as output an object which
holds the UMEM ID returned by the firmware to this registered memory.

The user can ask for specific page sizes for the given address and length, in that
case *mlx5dv_devx_umem_reg_ex()* should be used.
In case the kernel couldn't find a matching page size from the given *umem_in->pgsz_bitmap* bitmap
the API will fail.

The user will use that UMEM ID in device direct commands that use this memory
instead of the physical addresses list, for example upon
*mlx5dv_devx_obj_create* to create a QP.

# ARGUMENTS
*context*
:       RDMA device context to create the action on.

*addr*
:	The memory start address to register.

*size*
:       The size of *addr* buffer.

*access*
:	The desired memory protection attributes; it is either 0 or the bitwise OR of one or more of *enum ibv_access_flags*.

*umem_in*
:	A structure holds the legacy arguments in addition to a *pgsz_bitmap* field which represents the required page sizes.
	A *comp_mask* field was added for future use, for now must be 0.

# RETURN VALUE

Upon success *mlx5dv_devx_umem_reg* / *mlx5dv_devx_umem_reg_ex* will return a new *struct
mlx5dv_devx_umem* object, on error NULL will be returned and errno will be set.

*mlx5dv_devx_umem_dereg* returns 0 on success, or the value of errno on failure (which indicates the failure reason).

# SEE ALSO

*mlx5dv_open_device(3)*, *ibv_reg_mr(3)*, *mlx5dv_devx_obj_create(3)*

#AUTHOR

Yishai Hadas <yishaih@mellanox.com>
