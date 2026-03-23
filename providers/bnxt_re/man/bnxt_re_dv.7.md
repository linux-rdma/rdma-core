---
layout: page
title: BNXT_RE_DV
section: 7
tagline: Verbs
date: 2025-06-17
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv - Direct verbs for Broadcom RoCE (bnxt_re) devices

# DESCRIPTION

The libibverbs API is abstract and portable. For workloads that need to
manage some of the RDMA HW resources directly, the bnxt_re provider
exposes **direct verbs**. These are driver-specific routines that work
together with user-registered queue memory and optional doorbell regions.

To use these new interfaces, include `<infiniband/bnxt_re_dv.h>` and link
against **libbnxt_re** (in addition to **libibverbs**).

The following Direct Verbs are supported:

**Doorbell regions**

- **bnxt_re_dv_alloc_db_region**(3), **bnxt_re_dv_free_db_region**(3) allocate
  and release extra doorbell mapping regions.
- **bnxt_re_dv_get_default_db_region**(3) returns the default doorbell page index
  and user-mapped doorbell address for the context.

**User memory (umem)**

- **bnxt_re_dv_umem_reg**(3) records a user virtual range (and optional dmabuf
  metadata) for later use when creating resources. The library does not pin or
  map the memory at registration time; mapping occurs when a resource that uses
  the umem is created.
- **bnxt_re_dv_umem_dereg**(3) releases the registration.

**Completion queues**

- **bnxt_re_dv_create_cq**(3) creates a CQ backed by memory described by a prior
  **bnxt_re_dv_umem_reg**(3) handle and offset.
- **bnxt_re_dv_destroy_cq**(3) destroys such a CQ.

Applications may register one large buffer with **bnxt_re_dv_umem_reg**(3) and
pass different offsets (aligned to the device page size) and lengths when
creating individual CQs.

# SEE ALSO

**verbs**(7),
**bnxt_re_dv_alloc_db_region**(3),
**bnxt_re_dv_free_db_region**(3),
**bnxt_re_dv_get_default_db_region**(3),
**bnxt_re_dv_umem_reg**(3),
**bnxt_re_dv_umem_dereg**(3),
**bnxt_re_dv_create_cq**(3),
**bnxt_re_dv_destroy_cq**(3)

# AUTHORS

Kalesh AP \<kalesh-anakkur.purayil@broadcom.com\>,
Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>,
Selvin Xavier \<selvin.xavier@broadcom.com\>
