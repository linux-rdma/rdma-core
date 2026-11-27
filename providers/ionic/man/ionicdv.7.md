---
layout: page
title: IONICDV
section: 7
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionicdv - Direct verbs for ionic devices

This provides low level access to ionic devices to perform direct operations,
without general branching performed by libibverbs.

# DESCRIPTION

The libibverbs API is an abstract one. It is agnostic to any underlying
provider specific implementation. While this abstraction has the advantage
of user applications portability, it has a performance penalty. For some
applications optimizing performance is more important than portability.

The ionic direct verbs API is intended for such applications.
It exposes ionic specific low level operations, allowing the application
to bypass the libibverbs API.

The direct include of ionic_dv.h together with linkage to the ionic library
will allow usage of this new interface.

## UDMA Pipelines

Ionic devices expose multiple UDMA pipelines. Queues can be assigned to
specific pipelines by setting a UDMA mask on the protection domain before
creating queues. Use **ionic_dv_ctx_get_udma_count**(3) and
**ionic_dv_ctx_get_udma_mask**(3) to query the available pipelines, and
**ionic_dv_pd_set_udma_mask**(3) to restrict queue placement.

## Controller Memory Bar (CMB)

Send and receive queues can optionally be placed in the controller memory
bar for lower latency doorbell operations. Express doorbell optimizations
may also be enabled. Use **ionic_dv_pd_set_sqcmb**(3) and
**ionic_dv_pd_set_rqcmb**(3) to configure CMB preferences on a protection
domain before creating queues.

## RCCL and RCQ

Ionic devices support passing RCCL (RC Collective) flags and Reorder
Completion Queue (RCQ) selection from userspace to firmware at QP creation
time. RCCL flags control data, read fence, and receive offload capabilities
on RC queue pairs. RCQ reorders out-of-order receive completions so that
they are delivered to the application in order. Use
**ionic_dv_create_qp_ex**(3) to create a QP with these ionic-specific
attributes.

## dma-buf rings

CQ, SQ and RQ rings can be placed in dma-buf memory through a parent domain
created with **IBV_PARENT_DOMAIN_INIT_ATTR_BUF_ALLOCATORS** (see
**ibv_alloc_parent_domain**(3)). The alloc_buf callback returns a handle
from **ibv_alloc_user_buf_ex**() (see **ibv_alloc_user_buf**(3)) that carries the dma-buf fd and the
offset of the ring within the dma-buf, so several rings can share one
dma-buf. The handle must also carry a CPU mapping of the ring, because the
provider reads and writes ring entries directly.

dma-buf rings require kernel support for CQ and QP ring buffer descriptors.
On older kernels, queue creation fails with **EOPNOTSUPP** when the
alloc_buf callback returns a dma-buf handle. Handles without a dma-buf fd
are passed as virtual address buffers.

# SEE ALSO

**ibv_alloc_parent_domain**(3),
**ibv_alloc_user_buf**(3),
**ionic_dv_create_qp_ex**(3),
**ionic_dv_ctx_get_udma_count**(3),
**ionic_dv_ctx_get_udma_mask**(3),
**ionic_dv_pd_get_udma_mask**(3),
**ionic_dv_pd_set_udma_mask**(3),
**ionic_dv_pd_set_sqcmb**(3),
**ionic_dv_pd_set_rqcmb**(3),
**verbs**(7)

# AUTHORS

Advanced Micro Devices, Inc.
