---
layout: page
title: IONIC_DV_GET_CTX
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_get_ctx - Extract context information for GPU-initiated RDMA

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

int ionic_dv_get_ctx(struct ionic_dv_ctx *dvctx, struct ibv_context *ibctx);
```

# DESCRIPTION

**ionic_dv_get_ctx()** extracts device context information needed for
GPU-initiated RDMA operations into the *dvctx* structure.

The returned information includes:

- **db_page** / **db_ptr**: The memory mapped doorbell page and pointer
  that the GPU uses to ring doorbells.
- **sq_qtype**, **rq_qtype**, **cq_qtype**: Queue type identifiers used
  in doorbell encoding.

This function is used together with **ionic_dv_get_cq**(3) and
**ionic_dv_get_qp**(3) to obtain all information needed for a GPU to
directly operate on ionic queues.

# ARGUMENTS

*dvctx*
:	Output structure to receive the context information.

*ibctx*
:	The device context to query. Must be an ionic device context.

# RETURN VALUE

Returns 0 on success, or a positive errno value on failure:

*EPERM*
:	*ibctx* is not an ionic device context.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_qp_set_gda**(3),
**ionic_dv_get_cq**(3),
**ionic_dv_get_qp**(3)

# AUTHORS

Advanced Micro Devices, Inc.
