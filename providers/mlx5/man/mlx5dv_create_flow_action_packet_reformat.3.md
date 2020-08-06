
---
layout: page
title: mlx5dv_create_flow_action_packet_reformat
section: 3
tagline: Verbs
---

# NAME

mlx5dv_create_flow_action_packet_reformat - Flow action reformat packet for mlx5 provider

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct ibv_flow_action *
mlx5dv_create_flow_action_packet_reformat(struct ibv_context *ctx,
					  size_t data_sz,
					  void *data,
					  enum mlx5dv_flow_action_packet_reformat_type reformat_type,
					  enum mlx5dv_flow_table_type ft_type)
```

# DESCRIPTION

Create a packet reformat flow steering action.
It allows adding/removing packet headers.

# ARGUMENTS
*ctx*
:       RDMA device context to create the action on.

*data_sz*
:       The size of *data* buffer.

*data*
:       A buffer which contains headers in case the actions requires them.

*reformat_type*
:       The reformat type to be create. Use enum mlx5dv_flow_action_packet_reformat_type.
	MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TUNNEL_TO_L2: Decap a generic L2
	tunneled packet up to inner L2.

	MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L2_TUNNEL: Generic encap, *data*
		should contain the encapsulating headers.

	MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L3_TUNNEL_TO_L2: Will do decap where
		the inner packet starts from L3. *data* should be MAC or MAC + vlan (14 or 18 bytes) to be
		appended to the packet after the decap action.

	MLX5DV_FLOW_ACTION_PACKET_REFORMAT_TYPE_L2_TO_L3_TUNNEL: Will do encap where is
		L2 of the original packet will not be included. *data* should be the encapsulating header.

*ft_type*
:       It defines the flow table type to which the packet reformat action
	will be attached.

# RETURN VALUE

Upon success *mlx5dv_create_flow_action_packet_reformat* will return a new *struct
ibv_flow_action* object, on error NULL will be returned and errno will be set.

# SEE ALSO

*ibv_create_flow(3)*, *ibv_create_flow_action(3)*

