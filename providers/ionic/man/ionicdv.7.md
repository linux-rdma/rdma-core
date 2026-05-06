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

# SEE ALSO

**ionic_dv_ctx_get_udma_count**(3),
**ionic_dv_ctx_get_udma_mask**(3),
**ionic_dv_pd_get_udma_mask**(3),
**ionic_dv_pd_set_udma_mask**(3),
**ionic_dv_pd_set_sqcmb**(3),
**ionic_dv_pd_set_rqcmb**(3),
**verbs**(7)

# AUTHORS

Advanced Micro Devices, Inc.
