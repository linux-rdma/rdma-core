---
layout: page
title: IONIC_DV_GET_QP
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_get_qp - Extract queue pair information for GPU-initiated RDMA

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

int ionic_dv_get_qp(struct ionic_dv_qp *dvqp, struct ibv_qp *ibqp);
```

# DESCRIPTION

**ionic_dv_get_qp()** extracts send and receive queue descriptor
information into the *dvqp* structure. Each **ionic_dv_queue** in the
returned structure contains the queue buffer pointer, size, doorbell
value, mask, and log2 depth and stride.

This function is used together with **ionic_dv_get_ctx**(3) and
**ionic_dv_get_cq**(3) to obtain all information needed for a GPU to
directly operate on ionic queues in GDA mode.

# ARGUMENTS

*dvqp*
:	Output structure to receive the send and receive queue descriptors.

*ibqp*
:	The queue pair to query. Must be an ionic queue pair.

# RETURN VALUE

Returns 0 on success, or a positive errno value on failure:

*EPERM*
:	*ibqp* is not an ionic queue pair.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_get_ctx**(3),
**ionic_dv_get_cq**(3),
**ionic_dv_qp_set_gda**(3)

# AUTHORS

Advanced Micro Devices, Inc.
