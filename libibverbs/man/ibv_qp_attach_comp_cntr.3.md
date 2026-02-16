---
date: 2026-02-09
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_qp_attach_comp_cntr
tagline: Verbs
---

# NAME

**ibv_qp_attach_comp_cntr** - Attach a completion counter to a QP

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_qp_attach_comp_cntr(struct ibv_qp *qp,
                            struct ibv_comp_cntr *comp_cntr,
                            struct ibv_comp_cntr_attach_attr *attr);
```

# DESCRIPTION

**ibv_qp_attach_comp_cntr**() attaches the completion counter *comp_cntr* to
the queue pair *qp*. The *attr* argument specifies which operation types
should update the counter.

The QP must be in **IBV_QPS_RESET** or **IBV_QPS_INIT** state when attaching
a completion counter. Attempting to attach a counter to a QP in any other
state will fail with EINVAL.

The completion counter starts collecting values for the specified QP once
attached. Attaching the same completion counter to multiple QPs will
accumulate values from all attached QPs into the same counter.

Multiple completion counters can be attached to the same QP, provided their
*op_mask* values do not overlap. Attempting to attach a counter with an
*op_mask* that conflicts with an already attached counter will fail.

The *op_mask* field controls which operation completions are counted. Local
operations (**IBV_COMP_CNTR_ATTACH_OP_SEND**, **IBV_COMP_CNTR_ATTACH_OP_RECV**,
**IBV_COMP_CNTR_ATTACH_OP_RDMA_READ**, **IBV_COMP_CNTR_ATTACH_OP_RDMA_WRITE**)
count completions initiated by the local QP. Remote operations
(**IBV_COMP_CNTR_ATTACH_OP_REMOTE_RDMA_READ**,
**IBV_COMP_CNTR_ATTACH_OP_REMOTE_RDMA_WRITE**) count completions of incoming
RDMA operations initiated by the remote side. Supported *op_mask* values may
vary by device; unsupported values will result in an ENOTSUP error.

There is no explicit detach operation. A completion counter is implicitly
detached when the QP it is attached to is destroyed. A completion counter
cannot be destroyed while it is still attached to any QP; the QP must be
destroyed first.

# ARGUMENTS

*qp*
:	The queue pair to attach the completion counter to.

*comp_cntr*
:	The completion counter to attach, previously created with
	**ibv_create_comp_cntr**().

*attr*
:	Attach attributes specifying which operation types update the counter.

## ibv_comp_cntr_attach_attr

```c
enum ibv_comp_cntr_attach_op {
	IBV_COMP_CNTR_ATTACH_OP_SEND                    = 1 << 0,
	IBV_COMP_CNTR_ATTACH_OP_RECV                    = 1 << 1,
	IBV_COMP_CNTR_ATTACH_OP_RDMA_READ               = 1 << 2,
	IBV_COMP_CNTR_ATTACH_OP_REMOTE_RDMA_READ        = 1 << 3,
	IBV_COMP_CNTR_ATTACH_OP_RDMA_WRITE              = 1 << 4,
	IBV_COMP_CNTR_ATTACH_OP_REMOTE_RDMA_WRITE       = 1 << 5,
};

struct ibv_comp_cntr_attach_attr {
	uint32_t comp_mask;
	uint32_t op_mask;
};
```

*comp_mask*
:	Bitmask specifying what fields in the structure are valid.

*op_mask*
:	Bitmask of **ibv_comp_cntr_attach_op** values specifying which
	operation types should update the counter.

# RETURN VALUE

**ibv_qp_attach_comp_cntr**() returns 0 on success, or the value of errno on
failure (which indicates the failure reason).

# ERRORS

EINVAL
:	Invalid argument(s) passed.

ENOTSUP
:	Requested operation is not supported on this device.

EBUSY
:	The *op_mask* overlaps with a completion counter already attached
	to this QP.

# SEE ALSO

**ibv_create_comp_cntr**(3), **ibv_create_qp**(3)

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
