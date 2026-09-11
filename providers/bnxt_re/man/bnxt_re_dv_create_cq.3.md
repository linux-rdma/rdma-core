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
	struct ibv_buf *umem_handle; /* handle from ibv_alloc_user_buf() */
	uint64_t        umem_offset; /* byte offset into umem, page-aligned */
	uint32_t        ncqe;        /* number of CQ entries requested */
};
```

# DESCRIPTION

**bnxt_re_dv_create_cq**() creates a completion queue using memory described
by **ibv_alloc_user_buf**(3). The **umem_handle** field must be the handle
returned by that function; **umem_offset** is the byte offset into that
buffer, aligned to the device page size; **ncqe** is the requested number
of CQEs.

This call requires Linux kernel 7.2 or later; on older kernels it fails.

A CQ created this way is destroyed like any other CQ, using
**ibv_destroy_cq**(3).

# RETURN VALUE

Returns a pointer to the created **ibv_cq** on success, or NULL on failure with
errno set.

# SEE ALSO

**bnxt_re_dv**(7),
**ibv_alloc_user_buf**(3),
**ibv_create_cq**(3),
**ibv_destroy_cq**(3)

# AUTHORS

Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>,
Kalesh AP \<kalesh-anakkur.purayil@broadcom.com\>,
Selvin Xavier \<selvin.xavier@broadcom.com\>
