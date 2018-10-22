---
layout: page
title: mlx5dv_devx_alloc_uar / mlx5dv_devx_free_uar
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_alloc_uar -  Allocates a DEVX UAR

mlx5dv_devx_free_uar -   Frees a DEVX UAR

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_devx_uar *mlx5dv_devx_alloc_uar(struct ibv_context *context,
                                              uint32_t flags);

void mlx5dv_devx_free_uar(struct mlx5dv_devx_uar *devx_uar);
```

# DESCRIPTION

Create / free a DEVX UAR which is needed for other device commands over the DEVX interface.

The DEVX API enables direct access from the user space area to the mlx5 device
driver, the UAR information is needed for few commands as of QP creation.


# ARGUMENTS
*context*
:	RDMA device context to work on.

*flags*
:	Allocation flags for the UAR.

## devx_uar

```c
struct mlx5dv_devx_uar {
	void *reg_addr;
	void *base_addr;
	uint32_t page_id;
	off_t mmap_off;
	uint64_t comp_mask;
};
```
*reg_addr*
:	The write address of DB/BF.

*base_addr*
:	The base address of the UAR.

*page_id*
:	The device page id to be used.

*mmap_off*
:	The mmap offset parameter to be used for re-mapping, to be used by a secondary process.

# RETURN VALUE

Upon success *mlx5dv_devx_alloc_uar* will return a new *struct
mlx5dv_devx_uar*,  on error NULL will be returned and errno will be set.

# SEE ALSO

**mlx5dv_open_device**, **mlx5dv_devx_obj_create**

#AUTHOR

Yishai Hadas  <yishaih@mellanox.com>
