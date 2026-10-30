---
layout: page
title: IONIC_DV_CQ_GET_UDMA_MASK
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_cq_get_udma_mask - Get UDMA pipeline mask of a completion queue

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

uint8_t ionic_dv_cq_get_udma_mask(struct ibv_cq *ibcq);
```

# DESCRIPTION

**ionic_dv_cq_get_udma_mask()** returns the bitmask of UDMA pipelines
assigned to the completion queue *ibcq*. Each set bit represents a UDMA
pipeline that the completion queue spans.

A completion queue inherits its UDMA mask from the protection domain at
creation time via **ionic_dv_pd_set_udma_mask**(3).

# ARGUMENTS

*ibcq*
:	The completion queue to query. Must be an ionic completion queue.

# RETURN VALUE

Returns the UDMA pipeline bitmask of the completion queue. Returns 0 if
*ibcq* is not an ionic completion queue.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_ctx_get_udma_count**(3),
**ionic_dv_ctx_get_udma_mask**(3),
**ionic_dv_pd_get_udma_mask**(3),
**ionic_dv_pd_set_udma_mask**(3)

# AUTHORS

Advanced Micro Devices, Inc.
