---
layout: page
title: mlx5dv_reg_dmabuf_mr
section: 3
tagline: Verbs
---

# NAME

mlx5dv_reg_dmabuf_mr - Register a dma-buf based memory region (MR)

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct ibv_mr *mlx5dv_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset,
                                    size_t length, uint64_t iova, int fd,
                                    int access, int mlx5_access)
```

# DESCRIPTION

Register a dma-buf based memory region (MR), it follows the functionality of
*ibv_reg_dmabuf_mr()* with the ability to supply specific mlx5 access flags.

# ARGUMENTS
*pd*
:	The associated protection domain.

*offset*
:	The offset of the dma-buf where the MR starts.

*length*
:       The length of the MR.

*iova*
:	Specifies the virtual base address of the MR when accessed through a lkey or rkey.
	It must have the same page offset as *offset* and be aligned with the system page size.

*fd*
:	The file descriptor that the dma-buf is identified by.

*access*
:	The desired memory protection attributes; it is either 0 or the bitwise OR of one or more of *enum ibv_access_flags*.

*mlx5_access*
:	A specific device access flags, it is either 0 or the below.

	*MLX5DV_REG_DMABUF_ACCESS_DATA_DIRECT*
		if set, this MR will be accessed through the Data Direct engine bonded with that RDMA device.

# RETURN VALUE

Upon success returns a pointer to the registered MR, or NULL if the request fails, in that case the value of errno indicates the failure reason.

# SEE ALSO

*ibv_reg_dmabuf_mr(3)*, *mlx5dv_get_data_direct_sysfs_path(3)*

# AUTHOR

Yishai Hadas <yishaih@nvidia.com>
