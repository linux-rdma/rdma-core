---
layout: page
title: mlx5dv_dm_map_op_addr
section: 3
tagline: Verbs
date: 2021-1-21
header: "mlx5 Programmer's Manual"
footer: mlx5
---

# NAME

mlx5dv_dm_map_op_addr - Get operation address of a device memory (DM)

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

void *mlx5dv_dm_map_op_addr(struct ibv_dm *dm, uint8_t op);
```

# DESCRIPTION

**mlx5dv_dm_map_op_addr()** returns a mmaped address to the device memory for the
requested **op**.

# ARGUMENTS

*dm*
:       The associated ibv_dm for this operation.

*op*
:       Indicates the DM operation type, based on device specification.

# RETURN VALUE

Returns a pointer to the mmaped address, on error NULL will be returned and errno will be set.

# SEE ALSO

**ibv_alloc_dm**(3),
**mlx5dv_alloc_dm**(3),

# AUTHOR

Maor Gottlieb <maorg@nvidia.com>
