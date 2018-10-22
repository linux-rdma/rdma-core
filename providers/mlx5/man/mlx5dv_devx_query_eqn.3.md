---
layout: page
title: mlx5dv_devx_query_eqn
section: 3
tagline: Verbs
---

# NAME

mlx5dv_devx_query_eqn -  Query EQN for a given vector id.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_devx_query_eqn(struct ibv_context *context, uint32_t vector,
                          uint32_t *eqn);
```

# DESCRIPTION

Query EQN for a given input vector, the EQN is needed for other device commands over the DEVX interface.

The DEVX API enables direct access from the user space area to the mlx5 device
driver, the EQN information is needed for few commands such as CQ creation.


# ARGUMENTS
*context*
:	RDMA device context to work on.

*vector*
:	Completion vector number.

*eqn*
:	The device EQ number which relates to the given input vector.

# RETURN VALUE

returns 0 on success, or the value of errno on failure (which indicates the failure reason).

# SEE ALSO

**mlx5dv_open_device**, **mlx5dv_devx_obj_create**

#AUTHOR

Yishai Hadas  <yishaih@mellanox.com>
