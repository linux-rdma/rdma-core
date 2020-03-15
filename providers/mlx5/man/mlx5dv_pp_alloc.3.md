---
layout: page
title: mlx5dv_pp_alloc / mlx5dv_pp_free
section: 3
tagline: Verbs
---

# NAME

mlx5dv_pp_alloc -  Allocates a packet pacing entry

mlx5dv_pp_free -   Frees a packet pacing entry

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_pp *
mlx5dv_pp_alloc(struct ibv_context *context,
		size_t pp_context_sz,
		const void *pp_context,
		uint32_t flags);

void mlx5dv_pp_free(struct mlx5dv_pp *dv_pp);
```

# DESCRIPTION

Create / free a packet pacing entry which can be used for some device commands over the DEVX interface.

The DEVX API enables direct access from the user space area to the mlx5 device
driver, the packet pacing information is needed for few commands where a packet pacing index is needed.


# ARGUMENTS
*context*
:	RDMA device context to work on, need to be opened with DEVX support by using mlx5dv_open_device().

*pp_context_sz*
:	Length of *pp_context* input buffer.

*pp_context*
:	Packet pacing context according to the device specification.

*flags*
:	MLX5DV_PP_ALLOC_FLAGS_DEDICATED_INDEX:
		allocate a dedicated index.

## dv_pp

```c
struct mlx5dv_pp {
	uint16_t index;
};

```
*index*
:	The device index to be used.

# RETURN VALUE

Upon success *mlx5dv_pp_alloc* returns a pointer to the created packet pacing object, on error NULL
will be returned and errno will be set.

# SEE ALSO

**mlx5dv_open_device**, **mlx5dv_devx_obj_create**

# AUTHOR

Yishai Hadas  <yishaih@mellanox.com>
