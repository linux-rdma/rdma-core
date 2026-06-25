---
layout: page
title: bnxt_re_dv_create_qp
section: 3
tagline: Verbs
date: 2026-06-05
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_create_qp - create a queue pair using application-provided memory

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>

struct ibv_qp *bnxt_re_dv_create_qp(struct ibv_pd *pd,
                                    struct bnxt_re_dv_qp_init_attr *qp_attr);

struct bnxt_re_dv_qp_init_attr {
    /* Standard ibv parameters */
    enum ibv_qp_type  qp_type;
    uint32_t          max_send_wr;
    uint32_t          max_recv_wr;
    uint32_t          max_send_sge;
    uint32_t          max_recv_sge;
    uint32_t          max_inline_data;
    struct ibv_cq    *send_cq;
    struct ibv_cq    *recv_cq;
    struct ibv_srq   *srq;           /* NULL if not using an SRQ */

    /* Direct verbs parameters */
    uint64_t          qp_handle;         /* opaque handle embedded in CQEs */
    void             *dbr_handle;        /* bnxt_re_dv_alloc_db_region() handle,
                                            or NULL for the context default */
    void             *sq_umem_handle;    /* umem handle from bnxt_re_dv_umem_reg() */
    uint64_t          sq_umem_offset;    /* byte offset into SQ umem, page-aligned */
    uint32_t          sq_len;            /* SQ ring length in bytes (incl. MSN area) */
    uint32_t          sq_slots;          /* SQ depth in WQE slots */
    uint32_t          sq_npsn;           /* number of PSN entries */
    void             *rq_umem_handle;    /* umem handle from bnxt_re_dv_umem_reg() */
    uint64_t          rq_umem_offset;    /* byte offset into RQ umem, page-aligned */
    uint32_t          rq_len;            /* RQ ring length in bytes */
    uint64_t          comp_mask;         /* reserved, set to 0 */
};
```

# DESCRIPTION

**bnxt_re_dv_create_qp**() creates a queue pair whose send queue (SQ) and
receive queue (RQ) rings are backed by memory previously registered with
**bnxt_re_dv_umem_reg**(3). This allows the application to manage QP ring
memory directly.

**qp_handle** is an opaque value set by the library on successful return. It
is embedded in completion queue entries (CQEs) so the application can
correlate completions back to this QP. The application must not set this
field before the call; it is populated by the library.

**sq_umem_handle** must be a handle returned by **bnxt_re_dv_umem_reg**(3).
**sq_umem_offset** is the page-aligned byte offset into that registration
where the SQ ring starts. **sq_len** must cover the full ring including the
MSN (message sequence number) area. **sq_slots** is the SQ depth in WQE
slots and **sq_npsn** is the number of PSN entries; both must be set by the
application based on the ring memory it has allocated.

**rq_umem_handle** must be a handle returned by **bnxt_re_dv_umem_reg**(3)
for the RQ ring. If **srq** is set, **rq_umem_handle** and **rq_umem_offset**
are ignored.

If **dbr_handle** is NULL, the context's default doorbell page is used.
Otherwise it must be a pointer returned by **bnxt_re_dv_alloc_db_region**(3).

This path requires **IB_UVERBS_CORE_SUPPORT_ROBUST_UDATA** on the device
when **sq_umem_handle** is provided. Callers can check for this support via
**ibv_query_device_ex**(3).

# RETURN VALUE

Returns a pointer to the created **ibv_qp** on success, or NULL on failure
with errno set.

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_destroy_qp**(3),
**bnxt_re_dv_modify_qp**(3),
**bnxt_re_dv_query_qp**(3),
**bnxt_re_dv_umem_reg**(3),
**bnxt_re_dv_alloc_db_region**(3),
**ibv_create_qp**(3)

# AUTHORS

Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>,
Selvin Xavier \<selvin.xavier@broadcom.com\>
