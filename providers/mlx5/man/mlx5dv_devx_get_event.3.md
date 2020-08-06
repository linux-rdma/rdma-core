---
layout: page
title: mlx5dv_devx_get_event
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_get_event - Get an asynchronous event.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_devx_async_event_hdr {
	uint64_t	cookie;
	uint8_t		out_data[];
};

ssize_t mlx5dv_devx_get_event(struct mlx5dv_devx_event_channel *event_channel,
                              struct mlx5dv_devx_async_event_hdr *event_data,
                              size_t event_resp_len)

```

# DESCRIPTION

Get a device event on the given *event_channel*.
Post a successful subscription over the event channel by calling to mlx5dv_devx_subscribe_devx_event() the application should use this
API to get the response once an event has occurred.

Upon response the *cookie* that was supplied upon the subscription is returned and the *out_data* includes the data itself.
The *out_data* may be omitted in case the channel was created with the omit data flag.

The application must supply a large enough buffer to hold the event according to the device specification, the buffer size
is given by the input *event_resp_len* parameter.

# ARGUMENTS
*event_channel*
:       The channel to get the event over.

*event_data*
:	The output data from the asynchronous event.

*event_resp_len*
:	The output buffer size to hold the response.

# RETURN VALUE

Upon success *mlx5dv_devx_get_event* will return the number of bytes read, otherwise -1 will be returned and errno was set.

# NOTES

In case the *event_channel* was created with the omit data flag, events having the same type may be combined per subscription and be reported once with the matching *cookie*.
In that mode of work, ordering is not preserved between those events to other on this channel.

On the other hand, when each event should hold the device data ordering is preserved, however, events might be loose as of lack of kernel memory, in that case EOVERFLOW will be reported.

# SEE ALSO

*mlx5dv_open_device(3)*, *mlx5dv_devx_subscribe_devx_event(3)*

#AUTHOR

Yishai Hadas <yishaih@mellanox.com>
