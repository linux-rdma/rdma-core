---
layout: page
title: bnxt_re_dv_create_cq
section: 3
tagline: Verbs
date: 2025-06-17
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_create_cq - create a completion queue using application-provided memory

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>

struct ibv_cq *bnxt_re_dv_create_cq(struct ibv_context *ibvctx,
				    struct bnxt_re_dv_cq_init_attr *cq_attr);

struct bnxt_re_dv_cq_init_attr {
	void    *umem_handle; /* opaque handle from bnxt_re_dv_umem_reg() */
	uint64_t umem_offset; /* byte offset into the umem, page-aligned */
	uint32_t ncqe;        /* number of CQ entries requested */
};
```

# DESCRIPTION

**bnxt_re_dv_create_cq**() creates a completion queue using memory registered
with **bnxt_re_dv_umem_reg**(3). The **umem_handle** field must be the opaque
handle returned by that function; **umem_offset** is the byte offset into that
registration, aligned to the device page size; **ncqe** is the requested number
of CQEs.

This path requires **IB_UVERBS_CORE_SUPPORT_ROBUST_UDATA** (robust udata) on the
device; otherwise the call fails.

# RETURN VALUE

Returns a pointer to the created **ibv_cq** on success, or NULL on failure with
errno set.

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_destroy_cq**(3),
**bnxt_re_dv_umem_reg**(3),
**ibv_create_cq**(3)

# AUTHORS

Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>,
Kalesh AP \<kalesh-anakkur.purayil@broadcom.com\>,
Selvin Xavier \<selvin.xavier@broadcom.com\>
