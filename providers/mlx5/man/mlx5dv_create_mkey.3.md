---
layout: page
title: mlx5dv_create_mkey / mlx5dv_destroy_mkey
section: 3
tagline: Verbs
---

# NAME

mlx5dv_create_mkey -  Creates an indirect mkey

mlx5dv_create_mkey -  Destroys an indirect mkey

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_mkey_init_attr {
	struct ibv_pd	*pd;
	uint32_t	create_flags;
	uint16_t	max_entries;
};

struct mlx5dv_mkey {
	uint32_t	lkey;
	uint32_t	rkey;
};

struct mlx5dv_mkey *
mlx5dv_create_mkey(struct mlx5dv_mkey_init_attr *mkey_init_attr);

int mlx5dv_destroy_mkey(struct mlx5dv_mkey *mkey);

```

# DESCRIPTION

Create / destroy an indirect mkey.

Create an indirect mkey to enable application uses its specific device functionality.

# ARGUMENTS

##mkey_init_attr##

*pd*
:	ibv protection domain.

*create_flags*
:	MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT:
		Indirect mkey is being created.

*max_entries*
:	Requested max number of pointed entries by this indirect mkey.
	The function will update the *mkey_init_attr->max_entries* with the actual mkey value that was created; it will be greater than or equal to the value requested.

# RETURN VALUE

Upon success *mlx5dv_create_mkey* will return a new *struct
mlx5dv_mkey* on error NULL will be returned and errno will be set.

Upon success destroy 0 is returned or the value of errno on a failure.

# Notes

To let this functionality works a DEVX context should be opened by using *mlx5dv_open_device*.

# SEE ALSO

**mlx5dv_open_device**

#AUTHOR

Yishai Hadas  <yishaih@mellanox.com>
