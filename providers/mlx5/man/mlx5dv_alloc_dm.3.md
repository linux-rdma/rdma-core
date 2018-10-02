---
layout: page
title: mlx5dv_alloc_dm
section: 3
tagline: Verbs
date: 2018-9-1
header: "mlx5 Programmer's Manual"
footer: mlx5
---

# NAME

mlx5dv_alloc_dm - allocates device memory (DM)

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct ibv_dm *mlx5dv_alloc_dm(struct ibv_context *context,
			       struct ibv_alloc_dm_attr *dm_attr,
			       struct mlx5dv_alloc_dm_attr *mlx5_dm_attr)
```


# DESCRIPTION

**mlx5dv_alloc_dm()** allocates device memory (DM) with specific driver properties.

# ARGUMENTS

Please see *ibv_alloc_dm(3)* man page for *context* and *dm_attr*.

## mlx5_dm_attr

```c
struct mlx5dv_alloc_dm_attr {
	enum mlx5dv_alloc_dm_type type;
	uint64_t comp_mask;
};
```

*type*
:	The device memory type user wishes to allocate:

	MLX5DV_DM_TYPE_MEMIC
		Device memory of type MEMIC - On-Chip memory that
		can be allocated and used as memory region for
		transmitting/receiving packet directly from/to the
		memory on the chip.

	MLX5DV_DM_TYPE_STEERING_SW_ICM
		Device memory of type STEERING SW ICM - This memory
		is used by the device to store the packet steering
		tables and rules. Can be used for direct table and steering
		rules creation when allocated by a privileged user.

	MLX5DV_DM_TYPE_HEADER_MODIFY_SW_ICM
		Device memory of type HEADER MODIFY SW ICM - This memory
		is used by the device to store the packet header modification
		tables and rules. Can be used for direct table and header modification
		rules creation when allocated by a privileged user.

*comp_mask*
:	Bitmask specifying what fields in the structure are valid:
	Currently reserved and should be set to 0.

# RETURN VALUE

**mlx5dv_alloc_dm()**
returns a pointer to the created DM, on error NULL will be returned and errno will be set.


# SEE ALSO

**ibv_alloc_dm**(3),

# AUTHOR

Ariel Levkovich <lariel@mellanox.com>
