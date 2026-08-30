---
layout: page
title: IONIC_DV_QP_GET_UDMA_IDX
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_qp_get_udma_idx - Get UDMA pipeline index of a queue pair

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

uint8_t ionic_dv_qp_get_udma_idx(struct ibv_qp *ibqp);
```

# DESCRIPTION

**ionic_dv_qp_get_udma_idx()** returns the UDMA pipeline index assigned
to the queue pair *ibqp*. The pipeline index identifies which UDMA data
path the queue pair uses for its operations.

A queue pair is assigned to a UDMA pipeline at creation time based on
the UDMA mask of its protection domain. Use
**ionic_dv_pd_set_udma_mask**(3) to control pipeline assignment.

# ARGUMENTS

*ibqp*
:	The queue pair to query. Must be an ionic queue pair.

# RETURN VALUE

Returns the UDMA pipeline index of the queue pair. Returns 0 if *ibqp*
is not an ionic queue pair.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_ctx_get_udma_count**(3),
**ionic_dv_ctx_get_udma_mask**(3),
**ionic_dv_cq_get_udma_mask**(3),
**ionic_dv_pd_set_udma_mask**(3)

# AUTHORS

Advanced Micro Devices, Inc.
