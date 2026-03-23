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

**Completion queues**

- **bnxt_re_dv_create_cq**(3) creates a CQ backed by a prior
  **ibv_alloc_user_buf**(3) handle and offset. Such a CQ is destroyed like any
  other CQ, using **ibv_destroy_cq**(3).

Applications may create one large buffer with **ibv_alloc_user_buf**(3) and
pass different offsets (aligned to the device page size) and lengths when
creating individual CQs or QP rings.

**Queue pairs**

- **bnxt_re_dv_create_qp**(3) creates a QP whose SQ and RQ rings are backed by
  prior **ibv_alloc_user_buf**(3) handles and offsets. An optional doorbell
  region from **bnxt_re_dv_alloc_db_region**(3) may be supplied; if omitted
  the context default is used. Such a QP is destroyed like any other QP,
  using **ibv_destroy_qp**(3). Its attributes are modified using the standard
  **ibv_modify_qp**(3).

# SEE ALSO

**verbs**(7),
**bnxt_re_dv_alloc_db_region**(3),
**bnxt_re_dv_free_db_region**(3),
**bnxt_re_dv_get_default_db_region**(3),
**bnxt_re_dv_create_cq**(3),
**bnxt_re_dv_create_qp**(3),
**ibv_alloc_user_buf**(3),
**ibv_modify_qp**(3)

# AUTHORS

Kalesh AP \<kalesh-anakkur.purayil@broadcom.com\>,
Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>,
Selvin Xavier \<selvin.xavier@broadcom.com\>
