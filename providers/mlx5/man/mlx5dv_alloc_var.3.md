---
layout: page
title: mlx5dv_alloc_var / mlx5dv_free_var
section: 3
tagline: Verbs
---

# NAME

mlx5dv_alloc_var -  Allocates a VAR

mlx5dv_free_var -   Frees a VAR

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_var *
mlx5dv_alloc_var(struct ibv_context *context, uint32_t flags);

void mlx5dv_free_var(struct mlx5dv_var *dv_var);
```

# DESCRIPTION

Create / free a VAR which can be used for some device commands over the DEVX interface.

The DEVX API enables direct access from the user space area to the mlx5 device
driver, the VAR information is needed for few commands related to Virtio.


# ARGUMENTS
*context*
:	RDMA device context to work on.

*flags*
:	Allocation flags for the UAR.

## dv_var

```c
struct mlx5dv_var {
	uint32_t page_id;
	uint32_t length;
	off_t mmap_off;
	uint64_t comp_mask;
};
```
*page_id*
:	The device page id to be used.

*length*
:	The mmap length parameter to be used for mapping a VA to the allocated VAR entry.

*mmap_off*
:	The mmap offset parameter to be used for mapping a VA to the allocated VAR entry.

# RETURN VALUE

Upon success *mlx5dv_alloc_var* returns a pointer to the created VAR
,on error NULL will be returned and errno will be set.

# SEE ALSO

**mlx5dv_open_device**, **mlx5dv_devx_obj_create**

# AUTHOR

Yishai Hadas  <yishaih@mellanox.com>
