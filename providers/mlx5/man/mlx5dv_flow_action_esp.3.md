---
layout: page
title: mlx5dv_flow_action_esp
section: 3
tagline: Verbs
---

# NAME

mlx5dv_flow_action_esp - Flow action esp for mlx5 provider

# SYNOPSIS

```c
#include <infiniband/mlx5/mlx5dv.h>

struct ibv_flow_action *
mlx5dv_create_flow_action_esp(struct ibv_context *ctx,
			      struct ibv_flow_action_esp_attr *esp,
			      struct mlx5dv_flow_action_esp *mlx5_attr);
```

# DESCRIPTION

Create an IPSEC ESP flow steering action.  
This verb is identical to *ibv_create_flow_action_esp* verb, but allows mlx5 specific flags.

# ARGUMENTS

Please see *ibv_flow_action_esp(3)* man page for *ctx* and *esp*.

## *mlx5_attr* argument

```c
struct mlx5dv_flow_action_esp {
	uint64_t comp_mask;  /* Use enum mlx5dv_flow_action_esp_mask */
	uint32_t action_flags; /* Use enum mlx5dv_flow_action_flags */
};
```

*comp_mask*
:	Bitmask specifying what fields in the structure are valid (*enum mlx5dv_flow_action_esp_mask*).

*action_flags*
:	A bitwise OR of the various values described below.

	*MLX5DV_FLOW_ACTION_FLAGS_REQUIRE_METADATA*:  
	Each received and transmitted packet using offload is expected to carry metadata in the form of a L2 header  
        with ethernet type 0x8CE4, followed by 6 bytes of data and the original packet ethertype.

# NOTE

The ESN is expected to be placed in the IV field for egress packets.  
The 64 bit sequence number is written in big-endian over the 64 bit IV field.  
There is no need to call modify to update the ESN window on egress when this DV is used.

# SEE ALSO

*ibv_flow_action_esp(3)*,  *RFC 4106*

