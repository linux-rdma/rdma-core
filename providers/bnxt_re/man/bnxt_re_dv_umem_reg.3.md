---
layout: page
title: bnxt_re_dv_umem_reg
section: 3
tagline: Verbs
date: 2025-06-17
header: "Broadcom BNXT-RE Direct Verbs Manual"
footer: bnxt_re
---

# NAME

bnxt_re_dv_umem_reg - register user memory for direct resource creation

# SYNOPSIS

```c
#include <infiniband/bnxt_re_dv.h>

struct bnxt_re_dv_umem *bnxt_re_dv_umem_reg(struct ibv_context *ibvctx,
					    struct bnxt_re_dv_umem_reg_attr *in);
```

# DESCRIPTION

**bnxt_re_dv_umem_reg**() records a virtual address range (*in->addr*, *in->size*)
and related parameters for later use by direct verbs such as
**bnxt_re_dv_create_cq**(3). The library marks the range with **madvise**(2)
**MADV_DONTFORK** and stores the parameters; it does **not** pin or DMA-map the
memory at this call. Pinning and mapping happen when a resource that consumes the
umem is created.

If *in->comp_mask* includes **BNXT_RE_DV_UMEM_FLAGS_DMABUF**, *in->dmabuf_fd*
must be a valid file descriptor; otherwise **errno** is set to **EBADF**.

# ARGUMENTS

*in*
:	Pointer to a **struct bnxt_re_dv_umem_reg_attr** describing the memory
	region to register:

	```c
	struct bnxt_re_dv_umem_reg_attr {
	        void     *addr;      /* start of the virtual address range */
	        size_t    size;      /* length in bytes */
	        uint64_t  comp_mask; /* BNXT_RE_DV_UMEM_FLAGS_* */
	        int       dmabuf_fd; /* valid fd when BNXT_RE_DV_UMEM_FLAGS_DMABUF is set */
	};
	```

# RETURN VALUE

Returns an opaque **bnxt_re_dv_umem** pointer on success, or NULL on failure with
errno set.

# SEE ALSO

**bnxt_re_dv**(7),
**bnxt_re_dv_umem_dereg**(3),
**bnxt_re_dv_create_cq**(3),
**madvise**(2)

# AUTHORS

Kalesh AP \<kalesh-anakkur.purayil@broadcom.com\>,
Sriharsha Basavapatna \<sriharsha.basavapatna@broadcom.com\>
