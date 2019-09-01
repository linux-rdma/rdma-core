---
layout: page
title: mlx5dv_create_flow_matcher
section: 3
tagline: Verbs
date: 2018-9-19
header: "mlx5 Programmer's Manual"
footer: mlx5
---

# NAME
mlx5dv_create_flow_matcher - creates a matcher to be used with *mlx5dv_create_flow(3)*

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct mlx5dv_flow_matcher *
mlx5dv_create_flow_matcher(struct ibv_context *context,
			   struct mlx5dv_flow_matcher_attr *attr)
```

# DESCRIPTION

**mlx5dv_create_flow_matcher()** creates a flow matcher (mask) to be used
with *mlx5dv_create_flow(3)*.

# ARGUMENTS

Please see *ibv_open_device(3)* for *context*.

## *attr*

```c
struct mlx5dv_flow_matcher_attr {
	enum ibv_flow_attr_type type;
	uint32_t flags; /* From enum ibv_flow_flags */
	uint16_t priority;
	uint8_t match_criteria_enable; /* Device spec format */
	struct mlx5dv_flow_match_parameters *match_mask;
	uint64_t comp_mask;
	enum mlx5dv_flow_table_type ft_type;
};
```

*type*
:	Type of matcher to be created:
	IBV_FLOW_ATTR_NORMAL:
		Normal rule according to specification.

*flags*
:	special flags to control rule:
	0:
		Nothing or zero value means matcher will store ingress flow rules.
	IBV_FLOW_ATTR_FLAGS_EGRESS:
		Specified this matcher will store egress flow rules.

*priority*
:	See *ibv_create_flow(3)*.

*match_criteria_enable*
:	What match criteria is configured in *match_mask*, passed in
	device spec format.

## *match_mask*
```c
struct mlx5dv_flow_match_parameters {
	size_t match_sz;
	uint64_t match_buf[]; /* Device spec format */
};
```

*match_sz*
:	Size in bytes of *match_buf*.

*match_buf*
:	Set which mask to be used, passed in
	device spec format.

*comp_mask*
:	MLX5DV_FLOW_MATCHER_MASK_FT_TYPE for *ft_type*

## *ft_type*
Specified in which flow table type, the matcher will store the flow rules:
	MLX5DV_FLOW_TABLE_TYPE_NIC_RX: Specified this matcher will store ingress flow rules.
	MLX5DV_FLOW_TABLE_TYPE_NIC_TX Specified this matcher will store egress flow rules.
	MLX5DV_FLOW_TABLE_TYPE_FDB : Specified this matcher will store FDB rules.
	MLX5DV_FLOW_TABLE_TYPE_RDMA_RX: Specified this matcher will store ingress RDMA flow rules.

# RETURN VALUE

**mlx5dv_create_flow_matcher**
returns a pointer to *mlx5dv_flow_matcher*, on error NULL will be returned and errno will be set.

# SEE ALSO

*ibv_open_device(3)*, *ibv_create_flow(3)*

# AUTHOR

Mark Bloch <markb@mellanox.com>
