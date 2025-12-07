---
layout: page
title: mlx5dv_devx_uar_export_dmabuf_fd
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_uar_export_dmabuf_fd - export dmabuf fd for a given mlx5dv_devx_uar.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_devx_uar_export_dmabuf_fd(struct mlx5dv_devx_uar *devx_uar);
```

# DESCRIPTION

**mlx5dv_devx_uar_export_dmabuf_fd()** exports a dmabuf fd that is associated with the given
*devx_uar*.

The returned fd can be later used for DMA and RDMA operations associated with it.

Once the usage has been ended, close() should be called while supplying the fd.

This call will release resources that were earlier allocated using the **mlx5dv_devx_uar_export_dmabuf_fd()** API.

# ARGUMENTS

*devx_uar*
:	An mlx5dv_devx_uar pointer to export the dmabuf fd for its memory.

# RETURN VALUE

**mlx5dv_devx_uar_export_dmabuf_fd()** returns an fd number >= 0 upon success, or -1 if the request fails and errno set to the error.

# SEE ALSO

**ibv_reg_mr_ex**(3)
**ibv_dm_export_dmabuf_fd**(3)

# AUTHOR

Yishai Hadas <yishaih@nvidia.com>
