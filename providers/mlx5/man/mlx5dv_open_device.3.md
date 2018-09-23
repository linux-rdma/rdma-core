---
layout: page
title: mlx5dv_open_device
section: 3
tagline: Verbs
---

# NAME

mlx5dv_open_device - Open an RDMA device context for the mlx5 provider

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct ibv_context *
mlx5dv_open_device(struct ibv_device *device, struct mlx5dv_context_attr *attr);
```

# DESCRIPTION

Open an RDMA device context with specific mlx5 provider attributes.

# ARGUMENTS

*device*
:	RDMA device to open.

## *attr* argument

```c
struct mlx5dv_context_attr {
        uint32_t flags;
        uint64_t comp_mask;
};
```

*flags*
:       A bitwise OR of the various values described below.

        *MLX5DV_CONTEXT_FLAGS_DEVX*:
        Allocate a DEVX context

*comp_mask*
:       Bitmask specifying what fields in the structure are valid

# RETURN VALUE
Returns a pointer to the allocated device context, or NULL if the request fails.

# SEE ALSO

*ibv_open_device(3)*

# AUTHOR

Yishai Hadas <yishaih@mellanox.com>
