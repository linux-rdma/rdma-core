---
date: 2026-08-08
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_attach_mr
---

# NAME

ibv_attach_mr - attach a memory region to a queue pair

ibv_detach_mr - detach a memory region from a queue pair

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_attach_mr(struct ibv_qp *qp, struct ibv_mr *mr);

int ibv_detach_mr(struct ibv_qp *qp, struct ibv_mr *mr);
```

# DESCRIPTION

**ibv_attach_mr()** binds the memory region *mr* to the queue pair *qp*, so
that incoming requests on *qp* may reach it. **ibv_detach_mr()** releases
that binding.

Attaching a region narrows the memory an individual queue pair exposes,
rather than leaving every region in the protection domain reachable from
every queue pair in it. A device that supports this reports
*IBV_DEVICE_MR_QP_RESTRICTED* or *IBV_DEVICE_MR_QP_JOB_RESTRICTED* in
*device_cap_flags_ex*; see **ibv_query_device_ex**(3). Attaching is itself
the request.

*qp* MUST be an *IBV_QPT_RU* queue pair, and *mr* and *qp* MUST belong to the
same protection domain. A region restricted to a job needs
*IBV_DEVICE_MR_QP_JOB_RESTRICTED* and attaches only to a queue pair of that
job; any other region needs *IBV_DEVICE_MR_QP_RESTRICTED*.

A region is attached to one queue pair at a time. While it is attached it
cannot be deregistered or re-registered. Destroying the queue pair detaches
every region still attached to it.

# ARGUMENTS

## qp

The queue pair to attach the region to.

## mr

The memory region to attach, as returned by **ibv_reg_mr**(3) or
**ibv_reg_mr_ex**(3).

# RETURN VALUE

Both calls return 0 on success, or the value of *errno* on failure.
EOPNOTSUPP is returned if the provider does not implement the operation or
the device lacks the access class the region needs, EBUSY if the region is
already attached to a queue pair, and EINVAL for a queue pair or region that
does not qualify. **ibv_dereg_mr**(3) returns EBUSY for an attached region.

# NOTES

Attaching is one of three ways Ultra Ethernet narrows what a transfer may
reach; the others are restricting a memory region to a job with
*IBV_REG_MR_MASK_JKEY* and deriving a narrower memory region from an
existing one with *IBV_REG_MR_MASK_CUR_MR*. See **ibv_reg_mr**(3) and
**ibv_uet**(7).

# SEE ALSO

**ibv_reg_mr**(3),
**ibv_query_qp_semantics**(3),
**ibv_create_qp_ex**(3),
**ibv_alloc_pd**(3),
**ibv_uet**(7)

# AUTHOR

Eric Davis <eric.davis@broadcom.com>
