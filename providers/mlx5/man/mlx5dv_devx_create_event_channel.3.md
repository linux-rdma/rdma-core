---
layout: page
title: mlx5dv_devx_create_event_channel, mlx5dv_devx_destroy_event_channel
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_create_event_channel - Create an event channel to be used for DEVX asynchronous events.

mlx5dv_devx_destroy_event_channel - Destroy a DEVX event channel.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_devx_event_channel {
	int fd;
};

struct mlx5dv_devx_event_channel *
mlx5dv_devx_create_event_channel(struct ibv_context *context,
                                 enum mlx5dv_devx_create_event_channel_flags flags)

void mlx5dv_devx_destroy_event_channel(struct mlx5dv_devx_event_channel *event_channel)

```

# DESCRIPTION

Create or destroy a channel to be used for DEVX asynchronous events.

The create verb exposes an mlx5dv_devx_event_channel object that can be used to
read asynchronous DEVX events. This lets an application to subscribe to get
device events and once an event occurred read it from this object.

# ARGUMENTS
*context*
:       RDMA device context to create the channel on.

*flags*
:	MLX5DV_DEVX_CREATE_EVENT_CHANNEL_FLAGS_OMIT_EV_DATA:
		omit the event data on this channel.

# RETURN VALUE

Upon success *mlx5dv_devx_create_event_channel* will return a new *struct
mlx5dv_devx_event_channel* object, on error NULL will be returned and errno will be set.

# SEE ALSO

*mlx5dv_open_device(3)*, *mlx5dv_devx_obj_create(3)*

#AUTHOR

Yishai Hadas <yishaih@mellanox.com>
