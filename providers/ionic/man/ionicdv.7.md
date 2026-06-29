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

## Provider Detection

Applications that may run on different RDMA providers can use
**ionic_dv_is_ionic_ctx**(3), **ionic_dv_is_ionic_pd**(3),
**ionic_dv_is_ionic_cq**(3), and **ionic_dv_is_ionic_qp**(3)
to test whether a given verbs object belongs to the ionic provider
before calling ionic-specific direct verbs.

## UDMA Pipelines

Ionic devices expose multiple UDMA pipelines. Queues can be assigned to
specific pipelines by setting a UDMA mask on the protection domain before
creating queues. Use **ionic_dv_ctx_get_udma_count**(3) and
**ionic_dv_ctx_get_udma_mask**(3) to query the available pipelines, and
**ionic_dv_pd_set_udma_mask**(3) to restrict queue placement. After
creating queues, use **ionic_dv_cq_get_udma_mask**(3) to query the UDMA
mask assigned to a completion queue, and **ionic_dv_qp_get_udma_idx**(3)
to query the UDMA pipeline index assigned to a queue pair.

## Express Doorbell

Express doorbell optimizations can reduce doorbell overhead for certain
WQE sizes. By default, only 64-byte WQE express doorbell is enabled.
Use **ionic_dv_pd_set_expdb_mask**(3) to enable express doorbell for
additional WQE sizes on a protection domain.

## Controller Memory Bar (CMB)

Send and receive queues can optionally be placed in the controller memory
bar for lower latency doorbell operations. Express doorbell optimizations
may also be enabled. Use **ionic_dv_pd_set_sqcmb**(3) and
**ionic_dv_pd_set_rqcmb**(3) to configure CMB preferences on a protection
domain before creating queues.

## GPU-Direct Async (GDA)

GPU-Direct Async mode allows GPU-initiated RDMA operations. When GDA is
enabled on a queue pair, posting work requests writes WQEs without ringing
the doorbell. The GPU can then ring the doorbell directly by writing
doorbell data to the memory mapped doorbell register.

Use **ionic_dv_qp_set_gda**(3) to enable GDA mode on a queue pair.
After posting work, use **ionic_dv_qp_get_send_dbell_data**(3) and
**ionic_dv_qp_get_recv_dbell_data**(3) to obtain the doorbell data.
Use **ionic_dv_get_ctx**(3), **ionic_dv_get_cq**(3), and
**ionic_dv_get_qp**(3) to extract queue information for direct GPU
access.

# SEE ALSO

**ionic_dv_is_ionic_ctx**(3),
**ionic_dv_is_ionic_pd**(3),
**ionic_dv_is_ionic_cq**(3),
**ionic_dv_is_ionic_qp**(3),
**ionic_dv_ctx_get_udma_count**(3),
**ionic_dv_ctx_get_udma_mask**(3),
**ionic_dv_pd_get_udma_mask**(3),
**ionic_dv_pd_set_udma_mask**(3),
**ionic_dv_cq_get_udma_mask**(3),
**ionic_dv_qp_get_udma_idx**(3),
**ionic_dv_pd_set_expdb_mask**(3),
**ionic_dv_pd_set_sqcmb**(3),
**ionic_dv_pd_set_rqcmb**(3),
**ionic_dv_qp_set_gda**(3),
**verbs**(7)

# AUTHORS

Advanced Micro Devices, Inc.
