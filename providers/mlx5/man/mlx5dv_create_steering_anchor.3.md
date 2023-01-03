---
layout: page
title: mlx5dv_create_steering_anchor / mlx5dv_destroy_steering_anchor
section: 3
tagline: Verbs
---

# NAME

mlx5dv_create_steering_anchor - Creates a steering anchor

mlx5dv_destroy_steering_anchor - Destroys a steering anchor

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_steering_anchor *
mlx5dv_create_steering_anchor(struct ibv_context *context,
                              struct mlx5dv_steering_anchor_attr *attr);

int mlx5dv_destroy_steering_anchor(struct mlx5dv_steering_anchor *sa);
```

# DESCRIPTION

A user can take packets into a user-configured sandbox and do packet processing
at the end of which a steering pipeline decision is made on what to do with
the packet.

A steering anchor allows the user to reinject the packet back into the kernel
for additional processing.

**mlx5dv_create_steering_anchor()** Creates an anchor which will allow
injecting the packet back into the kernel steering pipeline.

**mlx5dv_destroy_steering_anchor()** Destroys a steering anchor.

# ARGUMENTS

## context

The device context to associate the steering anchor with.

## attr

Anchor attributes specify the priority and flow table type to which
the anchor will point.

```c
struct mlx5dv_steering_anchor_attr {
        enum mlx5dv_flow_table_type ft_type;
        uint16_t priority;
        uint64_t comp_mask;
};
```

*ft_type*

:	The flow table type to which the anchor will point.

*priority*

:	The priority inside *ft_type* to which the created anchor will point.

*comp_mask*

:	Reserved for future extension, must be 0 now.


## mlx5dv_steering_anchor

```c
struct mlx5dv_steering_anchor {
	uint32_t id;
};
```
*id*
:	The flow table ID to use as the destination when creating the flow table entry.

# RETURN VALUE

**mlx5dv_create_steering_anchor()** returns a pointer to a new
*mlx5dv_steering_anchor* on success. On error NULL is returned and errno is set.

**mlx5dv_destroy_steering_anchor()** returns 0 on success and errno value on error.

# AUTHORS

Mark Bloch <mbloch@nvidia.com>
