---
layout: page
title: mlx5dv_query_port
section: 3
tagline: Verbs
---

# NAME

mlx5dv_query_port - Query non standard attributes of IB device port.

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

int mlx5dv_query_port(struct ibv_context *context,
		      uint32_t port_num,
		      struct mlx5dv_port *info);

```

# DESCRIPTION

Query port info which can be used for some device commands over the DEVX interface and when directly
accessing the hardware resources.

A function that lets a user query hardware and configuration attributes associated with the port.

# USAGE

A user should provide the port number to query.
On successful query *flags* will store a subset of the requested attributes
which are supported/relevant for that port.

# ARGUMENTS

*context*
:	RDMA device context to work on.

*port_num*
:	Port number to query.

## *info*
:	Stores the returned attributes from the kernel.

```c
struct mlx5dv_port {
	uint64_t flags;
	uint16_t vport;
	uint16_t vport_vhca_id;
	uint16_t esw_owner_vhca_id;
	uint16_t rsvd0;
	uint64_t vport_steering_icm_rx;
	uint64_t vport_steering_icm_tx;
	struct mlx5dv_reg reg_c0;
};
```

*flags*
:	Bit field of attributes, on successful query *flags* stores the valid filled attributes.

	MLX5DV_QUERY_PORT_VPORT: The vport number of that port.

	MLX5DV_QUERY_PORT_VPORT_VHCA_ID: The VHCA ID of *vport_num*.

	MLX5DV_QUERY_PORT_ESW_OWNER_VHCA_ID: The E-Switch owner of *vport_num*.

	MLX5DV_QUERY_PORT_VPORT_STEERING_ICM_RX: The ICM RX address when directing traffic.

	MLX5DV_QUERY_PORT_VPORT_STEERING_ICM_TX: The ICM TX address when directing traffic.

	MLX5DV_QUERY_PORT_VPORT_REG_C0: Register C0 value used to identify egress of *vport_num*.

*vport*
:	The VPORT number of that port.

*vport_vhca_id*
:	The VHCA ID of *vport_num*.

*rsvd0*
:	A reserved field. Not to be used.

*esw_owner_vhca_id*
:	The E-Switch owner of *vport_num*.

*vport_steering_ica_rx*
:	 The ICM RX address when directing traffic.

*vport_steering_icm_tx*
:	The ICM TX address when directing traffic.

## reg_c0
:	Register C0 value used to identify traffic of *vport_num*.

```c
struct mlx5dv_reg {
        uint32_t value;
        uint32_t mask;
};
```

*value*
:	The value that should be used as match.

*mask*
:	The mask that should be used when matching.

# RETURN VALUE

returns 0 on success, or the value of errno on failure (which indicates the failure reason).

# EXAMPLE

```c
for (i = 1; i <= ports; i++) {
	ret = mlx5dv_query_port(context, i, &port_info);
	if (ret) {
		printf("Error querying port %d\n", i);
		break;
	}

	printf("Port: %d:\n", i);

	if (port_info.flags & MLX5DV_QUERY_PORT_VPORT)
		printf("\tvport_num: 0x%x\n", port_info.vport_num);

	if (port_info.flags & MLX5DV_QUERY_PORT_VPORT_REG_C0)
		printf("\treg_c0: val: 0x%x mask: 0x%x\n",
				port_info.reg_c0.value,
				port_info.reg_c0.mask);
}
```

Mark Bloch  <mbloch@nvidia.com>
