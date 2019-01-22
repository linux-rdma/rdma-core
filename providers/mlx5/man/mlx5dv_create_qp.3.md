---
layout: page
title: mlx5dv_create_qp
section: 3
tagline: Verbs
date: 2018-9-1
header: "mlx5 Programmer's Manual"
footer: mlx5
---

# NAME

mlx5dv_create_qp - creates a queue pair (QP)

# SYNOPSIS

```c
#include <infiniband/mlx5dv.h>

struct ibv_qp *mlx5dv_create_qp(struct ibv_context         *context,
                                struct ibv_qp_init_attr_ex *qp_attr,
                                struct mlx5dv_qp_init_attr *mlx5_qp_attr)
```


# DESCRIPTION

**mlx5dv_create_qp()** creates a queue pair (QP) with specific driver properties.

# ARGUMENTS

Please see *ibv_create_qp_ex(3)* man page for *context* and *qp_attr*.

## mlx5_qp_attr

```c
struct mlx5dv_qp_init_attr {
	uint64_t comp_mask;
	uint32_t create_flags;
	struct mlx5dv_dc_init_attr  dc_init_attr;
};
```

*comp_mask*
:	Bitmask specifying what fields in the structure are valid:
	MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS:
		valid values in *create_flags*
	MLX5DV_QP_INIT_ATTR_MASK_DC:
		valid values in *dc_init_attr*

*create_flags*
:	A bitwise OR of the various values described below.

	MLX5DV_QP_CREATE_TUNNEL_OFFLOADS:
		Enable offloading such as checksum and LRO for incoming
		tunneling traffic.

	MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_UC:
		Allow receiving loopback unicast traffic.

	MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_MC:
		Allow receiving loopback multicast traffic.

	MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE:
		Disable scatter to CQE feature which is enabled by default.

	MLX5DV_QP_CREATE_ALLOW_SCATTER_TO_CQE:
		Allow scatter to CQE for requester even if the qp was not
		configured to signal all WRs.

	MLX5DV_QP_CREATE_PACKET_BASED_CREDIT_MODE:
		Set QP to work in end-to-end packet-based credit,
		instead of the default message-based credits (IB spec. section 9.7.7.2). \
		It is the applications responsibility to make sure that the peer QP is configured with same mode.

*dc_init_attr*
:	DC init attributes.

## *dc_init_attr*

```c
struct mlx5dv_dc_init_attr {
	enum mlx5dv_dc_type	dc_type;
	uint64_t dct_access_key;
};
```

*dc_type*
:	MLX5DV_DCTYPE_DCT
		QP type: Target DC.
	MLX5DV_DCTYPE_DCI
		QP type: Initiator DC.

*dct_access_key*
:	used to create a DCT QP.


# RETURN VALUE

**mlx5dv_create_qp()**
returns a pointer to the created QP, on error NULL will be returned and errno will be set.


# SEE ALSO

**ibv_query_device_ex**(3), **ibv_create_qp_ex**(3),

# AUTHOR

Yonatan Cohen <yonatanc@mellanox.com>
