---
layout: page
title: mlx5dv_is_supported
section: 3
tagline: Verbs
---

# NAME

mlx5dv_is_supported - Check whether an RDMA device implemented by the mlx5 provider

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

bool mlx5dv_is_supported(struct ibv_device *device);
```

# DESCRIPTION

mlx5dv functions may be called only if this function returns true for the RDMA device.

# ARGUMENTS

*device*
:	RDMA device to check.

# RETURN VALUE
Returns true if device is implemented by mlx5 provider.

# SEE ALSO

*mlx5dv(7)*

# AUTHOR

Artemy Kovalyov <artemyko@mellanox.com>
