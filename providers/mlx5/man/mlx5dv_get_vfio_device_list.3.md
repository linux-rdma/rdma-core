---
layout: page
title: mlx5dv_get_vfio_device_list
section: 3
tagline: Verbs
---

# NAME

mlx5dv_get_vfio_device_list - Get list of available devices to be used over VFIO

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct ibv_device **
mlx5dv_get_vfio_device_list(struct mlx5dv_vfio_context_attr *attr);
```

# DESCRIPTION

Returns a NULL-terminated array of devices based on input *attr*.

# ARGUMENTS

*attr*
:	Describe the VFIO devices to return in list.

## *attr* argument

```c
struct mlx5dv_vfio_context_attr {
	const char *pci_name;
	uint32_t flags;
	uint64_t comp_mask;
};
```
*pci_name*
:      The PCI name of the required device.

*flags*
:       A bitwise OR of the various values described below.

        *MLX5DV_VFIO_CTX_FLAGS_INIT_LINK_DOWN*:
        Upon device initialization link should stay down.

*comp_mask*
:       Bitmask specifying what fields in the structure are valid.

# RETURN VALUE
Returns the array of the matching devices, or sets errno and returns NULL if the request fails.

# NOTES
Client  code  should open all the devices it intends to use with ibv_open_device() before calling ibv_free_device_list().  Once it frees the array with ibv_free_device_list(), it will be able to
use only the open devices; pointers to unopened devices will no longer be valid.

# SEE ALSO

*ibv_open_device(3)* *ibv_free_device_list(3)*

# AUTHOR

Yishai Hadas <yishaih@nvidia.com>
