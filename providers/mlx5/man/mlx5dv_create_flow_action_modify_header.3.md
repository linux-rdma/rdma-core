---
layout: page
title: mlx5dv_create_flow_action_modify_header
section: 3
tagline: Verbs
---

# NAME

mlx5dv_create_flow_action_modify_header - Flow action modify header for mlx5 provider

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct ibv_flow_action *
mlx5dv_create_flow_action_modify_header(struct ibv_context *ctx,
					size_t actions_sz,
					uint64_t actions[],
					enum mlx5dv_flow_table_type ft_type)
```

# DESCRIPTION

Create a modify header flow steering action, it allows mutating a packet header.

# ARGUMENTS

*ctx*
:	RDMA device context to create the action on.

*actions_sz*
:	The size of *actions* buffer in bytes.

*actions*
:	A buffer which contains modify actions provided in device spec format (i.e. be64).

*ft_type*
:	Defines the flow table type to which the modify header action will be attached.

	MLX5DV_FLOW_TABLE_TYPE_NIC_RX: RX FLOW TABLE

	MLX5DV_FLOW_TABLE_TYPE_NIC_TX: TX FLOW TABLE

# RETURN VALUE

Upon success *mlx5dv_create_flow_action_modify_header* will return a new *struct
ibv_flow_action* object, on error NULL will be returned and errno will be set.

# SEE ALSO

*ibv_create_flow(3)*, *ibv_create_flow_action(3)*

