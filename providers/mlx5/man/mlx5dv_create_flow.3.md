---
layout: page
title: mlx5dv_create_flow
section: 3
tagline: Verbs
date: 2018-9-19
header: "mlx5 Programmer's Manual"
footer: mlx5
---

# NAME
mlx5dv_create_flow - creates a steering flow rule

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct ibv_flow *
mlx5dv_create_flow(struct mlx5dv_flow_matcher *flow_matcher,
		   struct mlx5dv_flow_match_parameters *match_value,
		   size_t num_actions,
		   struct mlx5dv_flow_action_attr actions_attr[])
```


# DESCRIPTION
**mlx5dv_create_flow()** creates a steering flow rule with the ability
to specify specific driver properties.

# ARGUMENTS

Please see *mlx5dv_create_flow_matcher(3)* for *flow_matcher* and *match_value*.

*num_actions*
:	Specifies how many actions are passed in *actions_attr*

## *actions_attr*

```c
struct mlx5dv_flow_action_attr {
	enum mlx5dv_flow_action_type type;
	union {
		struct ibv_qp *qp;
		struct ibv_counters *counter;
		struct ibv_flow_action *action;
		uint32_t tag_value;
		struct mlx5dv_devx_obj *obj;
	};
};
```

*type*
:	MLX5DV_FLOW_ACTION_DEST_IBV_QP
		The QP passed will receive the matched packets.
	MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION
		The flow action to be applied.
	MLX5DV_FLOW_ACTION_TAG
		Flow tag to be provided in work completion.
	MLX5DV_FLOW_ACTION_DEST_DEVX
		The DEVX destination object for the matched packets.
	MLX5DV_FLOW_ACTION_COUNTERS_DEVX
		The DEVX counter object for the matched packets.

*qp*
:	QP passed, to be used with *type* *MLX5DV_FLOW_ACTION_DEST_IBV_QP*.

*action*
:	Flow action, to be used with *type* *MLX5DV_FLOW_ACTION_IBV_FLOW_ACTION*
	see *mlx5dv_create_flow_action_modify_header(3)* and *mlx5dv_create_flow_action_packet_reformat(3)*.

*tag_value*
:	tag value to be passed in the work completion, to be used with *type*
	*MLX5DV_FLOW_ACTION_TAG* see *ibv_create_cq_ex(3)*.

*obj*
:	DEVX object, to be used with *type* *MLX5DV_FLOW_ACTION_DEST_DEVX* or by *MLX5DV_FLOW_ACTION_COUNTERS_DEVX*.

# RETURN VALUE

**mlx5dv_create_flow**
returns a pointer to the created flow rule, on error NULL will be returned and errno will be set.

# SEE ALSO

*mlx5dv_create_flow_action_modify_header(3)*, *mlx5dv_create_flow_action_packet_reformat(3)*,
*mlx5dv_create_flow_matcher(3)*, *mlx5dv_create_qp(3)*, *ibv_create_qp_ex(3)*
*ibv_create_cq_ex(3)* *ibv_create_counters(3)*

# AUTHOR

Mark Bloch <marb@mellanox.com>
