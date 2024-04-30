---
layout: page
title: mlx5dv_get_data_direct_sysfs_path
section: 3
tagline: Verbs
---

# NAME

mlx5dv_get_data_direct_sysfs_path - Get the sysfs path of a data direct device

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_get_data_direct_sysfs_path(struct ibv_context *context, char *buf,
                                      size_t buf_len)
```

# DESCRIPTION

Get the sysfs path of the data direct device that is associated with the  given *context*.

This lets an application to discover whether/which data direct device is associated with the given *context*.

# ARGUMENTS
*context*
:	RDMA device context to work on.

*buf*
:	The buffer where to place the sysfs path of the associated data direct device.

*buf_len*
:       The length of the buffer.

# RETURN VALUE

Upon success 0 is returned or the value of errno on a failure.

# ERRORS

The below specific error values should be considered.

ENODEV

:       There is no associated data direct device for the given *context*.

ENOSPC

:       The input buffer size is too small to hold the full sysfs path.

# NOTES

Upon succees, the caller should add the /sys/ prefix to get the full sysfs path.

# SEE ALSO

*mlx5dv_reg_dmabuf_mr(3)*

# AUTHOR

Yishai Hadas <yishaih@nvidia.com>
