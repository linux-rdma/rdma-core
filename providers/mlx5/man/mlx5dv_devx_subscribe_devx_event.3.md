---
layout: page
title: mlx5dv_devx_subscribe_devx_event, mlx5dv_devx_subscribe_devx_event_fd
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_subscribe_devx_event - Subscribe over an event channel for device events.

mlx5dv_devx_subscribe_devx_event_fd - Subscribe over an event channel for device events to signal eventfd.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_devx_subscribe_devx_event(struct mlx5dv_devx_event_channel *dv_event_channel,
				     struct mlx5dv_devx_obj *obj,
				     uint16_t events_sz,
				     uint16_t events_num[],
				     uint64_t cookie)

int mlx5dv_devx_subscribe_devx_event_fd(struct mlx5dv_devx_event_channel *dv_event_channel,
					int fd,
					struct mlx5dv_devx_obj *obj,
					uint16_t event_num)
```

# DESCRIPTION

Subscribe over a DEVX event channel for device events.

# ARGUMENTS
*dv_event_channel*
:	Event channel to subscribe over.

*fd*
:	A file descriptor that previously was opened by the eventfd() system call.

*obj*
:	DEVX object that *events_num* relates to, can be NULL for unaffiliated events.

*events_sz*
:	Size of the *events_num* buffer that holds the events to subscribe for.

*events_num*
:	Holds the required event numbers to subscribe for, numbers are according to the device specification.

*cookie*
:	The value to be returned back when reading the event, can be used as an ID for application use.

# NOTES
When mlx5dv_devx_subscribe_devx_event_fd will be used the *fd* will be signaled once an event has occurred.


# SEE ALSO

*mlx5dv_open_device(3)*, *mlx5dv_devx_create_event_channel(3)*, *mlx5dv_devx_get_event(3)*

#AUTHOR

Yishai Hadas <yishaih@mellanox.com>
