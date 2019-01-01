---
layout: page
title: mlx5dv_devx_create_cmd_comp, mlx5dv_devx_destroy_cmd_comp
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_create_cmd_comp - Create a command completion to be used for DEVX asynchronous commands.

mlx5dv_devx_destroy_cmd_comp - Destroy a devx command completion.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_devx_cmd_comp {
	int fd;
};

struct mlx5dv_devx_cmd_comp *
mlx5dv_devx_create_cmd_comp(struct ibv_context *context)

void mlx5dv_devx_destroy_cmd_comp(struct mlx5dv_devx_cmd_comp *cmd_comp)
```

# DESCRIPTION

Create or destroy a command completion to be used for DEVX asynchronous commands.

The create verb exposes an mlx5dv_devx_cmd_comp object that can be used as part
of asynchronous DEVX commands. This lets an application run asynchronously
without blocking and once the response is ready read it from this object.

# ARGUMENTS
*context*
:       RDMA device context to create the action on.

*cmd_comp*
:	The command completion object.

# RETURN VALUE

Upon success *mlx5dv_devx_create_cmd_comp* will return a new *struct
mlx5dv_devx_cmd_comp* object, on error NULL will be returned and errno will be set.

# SEE ALSO

*mlx5dv_open_device(3)*, *mlx5dv_devx_obj_create(3)*

#AUTHOR

Yishai Hadas <yishaih@mellanox.com>
