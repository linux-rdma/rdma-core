---
layout: page
title: IONIC_DV_GET_CQ
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_get_cq - Extract completion queue information for GPU-initiated RDMA

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

int ionic_dv_get_cq(struct ionic_dv_cq *dvcq, struct ibv_cq *ibcq,
                    uint8_t udma_idx);
```

# DESCRIPTION

**ionic_dv_get_cq()** extracts completion queue descriptor information
for the UDMA pipeline *udma_idx* into the *dvcq* structure. The returned
**ionic_dv_queue** contains the queue buffer pointer, size, doorbell
value, mask, and log2 depth and stride.

A completion queue may span multiple UDMA pipelines. The *udma_idx*
selects which pipeline's CQ descriptor to extract. Use
**ionic_dv_cq_get_udma_mask**(3) to determine valid pipeline indices.

# ARGUMENTS

*dvcq*
:	Output structure to receive the CQ queue descriptor.

*ibcq*
:	The completion queue to query. Must be an ionic completion queue.

*udma_idx*
:	The UDMA pipeline index to extract. Must be a pipeline that the
	CQ spans (i.e., the corresponding bit must be set in the CQ's
	UDMA mask).

# RETURN VALUE

Returns 0 on success, or a positive errno value on failure:

*EPERM*
:	*ibcq* is not an ionic completion queue.

*EINVAL*
:	*udma_idx* is not a valid pipeline for this CQ.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_get_ctx**(3),
**ionic_dv_get_qp**(3),
**ionic_dv_cq_get_udma_mask**(3)

# AUTHORS

Advanced Micro Devices, Inc.
