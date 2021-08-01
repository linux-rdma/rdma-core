---
layout: page
title: mlx5dv_vfio_get_events_fd
section: 3
tagline: Verbs
---

# NAME

mlx5dv_vfio_get_events_fd - Get the file descriptor to manage driver events.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_vfio_get_events_fd(struct ibv_context *ctx);
```

# DESCRIPTION

Returns the file descriptor to be used for managing driver events.

# ARGUMENTS

*ctx*
:	device context that was opened for VFIO by calling mlx5dv_get_vfio_device_list().

# RETURN VALUE
Returns the internal matching file descriptor.

# NOTES
Client code should poll the returned file descriptor and once there is some data to be managed immediately call *mlx5dv_vfio_process_events()*.

# SEE ALSO

*ibv_open_device(3)* *ibv_free_device_list(3)* *mlx5dv_get_vfio_device_list(3)*

# AUTHOR

Yishai Hadas <yishaih@nvidia.com>
