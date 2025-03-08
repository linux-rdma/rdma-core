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

*attr*

## mlx5dv_context_attr

```c
struct mlx5dv_context_attr {
        uint32_t flags;
        uint64_t comp_mask;
        struct ibv_fd_arr *fds;
};
```

*flags*
:       A bitwise OR of the various values described below.

        *MLX5DV_CONTEXT_FLAGS_DEVX*:
        Allocate a DEVX context

*comp_mask*
:       Bitmask specifying what fields in the structure are valid

        *MLX5DV_CONTEXT_ATTR_MASK_FD_ARRAY*:
        Valid value in *fds*

*fds*
:       Used to pass a file descriptor array.

## ibv_fd_arr

```c
struct ibv_fd_arr {
        int *arr;
        uint32_t count;
};

```

*arr*
:      Pointer to the file descriptor array.

*count*
:      Number of elements in the array.

# RETURN VALUE
Returns a pointer to the allocated device context, or NULL if the request fails.

# SEE ALSO

*ibv_open_device(3)*

# AUTHOR

Yishai Hadas <yishaih@mellanox.com>
