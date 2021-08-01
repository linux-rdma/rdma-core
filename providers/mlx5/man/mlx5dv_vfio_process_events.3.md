---
layout: page
title: mlx5dv_vfio_process_events
section: 3
tagline: Verbs
---

# NAME

mlx5dv_vfio_process_events - process vfio driver events

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_vfio_process_events(struct ibv_context *ctx);
```

# DESCRIPTION

This API should run from application thread and maintain device events.
The application is responsible to get the events FD by calling *mlx5dv_vfio_get_events_fd()*
and once the FD is pollable call the API to let driver process its internal events.

# ARGUMENTS

*ctx*
:	device context that was opened for VFIO by calling mlx5dv_get_vfio_device_list().

# RETURN VALUE
Returns 0 upon success or errno value in case a failure has occurred.

# NOTES
Application can use this API also to periodically check the device health state even if no events exist.

# SEE ALSO

*ibv_open_device(3)* *ibv_free_device_list(3)* *mlx5dv_get_vfio_device_list(3)* *mlx5dv_vfio_get_events_fd(3)*

# AUTHOR

Yishai Hadas <yishaih@nvidia.com>
