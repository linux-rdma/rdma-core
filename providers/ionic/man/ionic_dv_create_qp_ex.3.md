---
layout: page
title: IONIC_DV_CREATE_QP_EX
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_create_qp_ex - Create a queue pair with ionic-specific attributes

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

struct ibv_qp *ionic_dv_create_qp_ex(struct ibv_context *ibctx,
                                     struct ibv_qp_init_attr_ex *ex,
                                     struct ionic_dv_qp_init_attr_ex *ionic_ex);
```

# DESCRIPTION

**ionic_dv_create_qp_ex()** creates a queue pair (QP) with ionic-specific
driver properties. It extends the standard **ibv_create_qp_ex**(3) interface
with ionic-specific attributes for configuring RCCL (RC Collective)
operations and Reorder Completion Queue (RCQ) behavior.

The caller specifies **IBV_QPT_RC** as the QP type in the standard *ex*
attributes. The returned QP always has *qp_type* == **IBV_QPT_RC**.

# ARGUMENTS

Please see *ibv_create_qp_ex(3)* man page for *ibctx* and *ex*.

## ionic_ex

```c
enum ionic_dv_qp_init_attr_mask {
	IONIC_DV_QP_INIT_ATTR_MASK_FLAGS = (1 << 0),
};

enum ionic_dv_qp_init_attr_flags {
	IONIC_DV_CREATE_QP_TYPE_RCCL       = 1 << 16,
	IONIC_DV_CREATE_QP_RCCL_DATA       = 1 << 17,
	IONIC_DV_CREATE_QP_RCCL_RDFENCE    = 1 << 18,
	IONIC_DV_CREATE_QP_RCCL_RX_OFFLOAD = 1 << 19,
	IONIC_DV_CREATE_QP_RCCL_RCQ        = 1 << 24,
};

struct ionic_dv_qp_init_attr_ex {
	uint64_t comp_mask;
	uint32_t ionic_flags;
};
```

*comp_mask*
:	Bitmask specifying what fields in the structure are valid.
	Composed of **ionic_dv_qp_init_attr_mask** values:

	**IONIC_DV_QP_INIT_ATTR_MASK_FLAGS**:
		Valid values in *ionic_flags*.

*ionic_flags*
:	A bitwise OR of the various values described below. Valid when
	*comp_mask* includes **IONIC_DV_QP_INIT_ATTR_MASK_FLAGS**.

	**IONIC_DV_CREATE_QP_TYPE_RCCL**:
		Create an RCCL (RC Collective) QP type.

	**IONIC_DV_CREATE_QP_RCCL_DATA**:
		Enable RCCL data operations on this QP.

	**IONIC_DV_CREATE_QP_RCCL_RDFENCE**:
		Enable RCCL read fence operations on this QP.

	**IONIC_DV_CREATE_QP_RCCL_RX_OFFLOAD**:
		Enable RCCL receive offload operations on this QP.

	**IONIC_DV_CREATE_QP_RCCL_RCQ**:
		Enable Reorder Completion Queue (RCQ) for this QP. When
		enabled, out-of-order receive completions are reordered
		so that completions are delivered to the application in
		order.

# RETURN VALUE

**ionic_dv_create_qp_ex()** returns a pointer to the created QP, or NULL
if the request fails (in which case *errno* is set to indicate the error).

# NOTES

The *ex->qp_type* field must be **IBV_QPT_RC**. The returned QP always
exposes *qp_type* == **IBV_QPT_RC** to the application.

Compatibility is handled through the *comp_mask* field. Applications
should only set bits for fields they intend to use. Unknown bits in
*comp_mask* are reserved for future extensions.

# EXAMPLES

```c
struct ibv_qp_init_attr_ex qp_attr = {
	.send_cq = cq,
	.recv_cq = cq,
	.cap = {
		.max_send_wr = 64,
		.max_recv_wr = 64,
		.max_send_sge = 4,
		.max_recv_sge = 4,
	},
	.qp_type = IBV_QPT_RC,
	.comp_mask = IBV_QP_INIT_ATTR_PD,
	.pd = pd,
};

struct ionic_dv_qp_init_attr_ex ionic_attr = {
	.comp_mask = IONIC_DV_QP_INIT_ATTR_MASK_FLAGS,
	.ionic_flags = IONIC_DV_CREATE_QP_RCCL_RCQ,
};

struct ibv_qp *qp = ionic_dv_create_qp_ex(ctx, &qp_attr, &ionic_attr);
```

# SEE ALSO

**ionicdv**(7),
**ibv_create_qp_ex**(3),
**ionic_dv_pd_set_udma_mask**(3),
**ionic_dv_pd_set_sqcmb**(3),
**ionic_dv_pd_set_rqcmb**(3)

# AUTHORS

Advanced Micro Devices, Inc.
