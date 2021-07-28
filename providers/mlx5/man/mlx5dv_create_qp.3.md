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
	uint64_t send_ops_flags;
};
```

*comp_mask*
:	Bitmask specifying what fields in the structure are valid:
	MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS:
		valid values in *create_flags*
	MLX5DV_QP_INIT_ATTR_MASK_DC:
		valid values in *dc_init_attr*
	MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS:
		valid values in *send_ops_flags*

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

	MLX5DV_QP_CREATE_SIG_PIPELINING:
		If the flag is set, the QP is moved to SQD state upon
		encountering a signature error, and IBV_EVENT_SQ_DRAINED is
		generated to inform about the new state. The signature
		pipelining feature is a performance optimization, which reduces
		latency for read operations in the storage protocols. The
		feature is optional. Creating the QP fails if the kernel or
		device does not support the feature. In this case, an
		application should fallback to backward compatibility mode
		and handle read operations without the pipelining. See details
		about the signature pipelining in
		**mlx5dv_qp_cancel_posted_send_wrs**(3).

*dc_init_attr*
:	DC init attributes.

## *dc_init_attr*

```c

struct mlx5dv_dci_streams {
	uint8_t log_num_concurent;
	uint8_t log_num_errored;
};

struct mlx5dv_dc_init_attr {
	enum mlx5dv_dc_type	dc_type;
	union {
	    uint64_t dct_access_key;
	    struct mlx5dv_dci_streams dci_streams;
	};
};
```

*dc_type*
:	MLX5DV_DCTYPE_DCT
		QP type: Target DC.
	MLX5DV_DCTYPE_DCI
		QP type: Initiator DC.

*dct_access_key*
:	used to create a DCT QP.

*dci_streams*
:	dci_streams used to define DCI QP with multiple concurrent streams.
	Valid when comp_mask includes MLX5DV_QP_INIT_ATTR_MASK_DCI_STREAMS.

	log_num_concurent
		Defines the number of parallel different streams that could be handled by HW.
		All work request of a specific stream_id are handled in order.

	log_num_errored
		Defines the number of dci error stream channels before moving DCI to an error state.

*send_ops_flags*
:	A bitwise OR of the various values described below.

	MLX5DV_QP_EX_WITH_MR_INTERLEAVED:
		Enables the mlx5dv_wr_mr_interleaved() work requset on this QP.

	MLX5DV_QP_EX_WITH_MR_LIST:
		Enables the mlx5dv_wr_mr_list() work requset on this QP.

	MLX5DV_QP_EX_WITH_MKEY_CONFIGURE:
		Enables the mlx5dv_wr_mkey_configure() work request and the
		related setters on this QP.

# NOTES

**mlx5dv_qp_ex_from_ibv_qp_ex()** is used to get *struct mlx5dv_qp_ex* for
accessing the send ops interfaces when IBV_QP_INIT_ATTR_SEND_OPS_FLAGS is used.

The MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE flag should be set in cases that IOVA doesn't
match the process' VA and the message payload size is small enough to trigger the scatter to CQE
feature.

When device memory is used IBV_SEND_INLINE and scatter to CQE should not be used, as the memcpy
is not possible.

# RETURN VALUE

**mlx5dv_create_qp()**
returns a pointer to the created QP, on error NULL will be returned and errno will be set.


# SEE ALSO

**ibv_query_device_ex**(3), **ibv_create_qp_ex**(3),

# AUTHOR

Yonatan Cohen <yonatanc@mellanox.com>
