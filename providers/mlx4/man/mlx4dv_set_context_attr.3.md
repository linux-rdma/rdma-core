---
layout: page
title: mlx4dv_set_context_attr
section: 3
tagline: Verbs
---

# NAME

mlx4dv_set_context_attr - Set context attributes

# SYNOPSIS

```c
#include <infiniband/mlx4dv.h>

int mlx4dv_set_context_attr(struct ibv_context *context,
                            enum mlx4dv_set_ctx_attr_type attr_type,
                            void *attr);
```

# DESCRIPTION

mlx4dv_set_context_attr gives the ability to set vendor specific attributes on
the RDMA context.

# ARGUMENTS
*context*
:	RDMA device context to work on.

*attr_type*
:	The type of the provided attribute.

*attr*
:	Pointer to the attribute to be set.
## attr_type

```c
enum mlx4dv_set_ctx_attr_type {
	/* Attribute type uint8_t */
	MLX4DV_SET_CTX_ATTR_LOG_WQS_RANGE_SZ	= 0,
	MLX4DV_SET_CTX_ATTR_BUF_ALLOCATORS	= 1,
};
```
*MLX4DV_SET_CTX_ATTR_LOG_WQS_RANGE_SZ*
:	Change the LOG WQs Range size for RSS

*MLX4DV_SET_CTX_ATTR_BUF_ALLOCATORS*
:	Provide an external buffer allocator

```c
struct mlx4dv_ctx_allocators {
	void *(*alloc)(size_t size, void *priv_data);
	void (*free)(void *ptr, void *priv_data);
	void *data;
};
```
*alloc*
:	Function used for buffer allocation instead of libmlx4 internal method

*free*
:	Function used to free buffers allocated by alloc function

*data*
:	Metadata that can be used by alloc and free functions

# RETURN VALUE
Returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

#AUTHOR

Majd Dibbiny  <majd@mellanox.com>
