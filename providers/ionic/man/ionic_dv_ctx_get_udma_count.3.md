---
layout: page
title: IONIC_DV_CTX_GET_UDMA_COUNT
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_ctx_get_udma_count - Get number of UDMA pipelines

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

uint8_t ionic_dv_ctx_get_udma_count(struct ibv_context *ibctx);
```

# DESCRIPTION

**ionic_dv_ctx_get_udma_count()** returns the number of UDMA pipelines
available on the ionic device associated with *ibctx*.

UDMA pipelines are independent data paths through the device. Queues can be
assigned to specific pipelines using **ionic_dv_pd_set_udma_mask**(3) on a
protection domain before creating the queues.

# ARGUMENTS

*ibctx*
:	The device context to query. Must be an ionic device context.

# RETURN VALUE

Returns the number of UDMA pipelines available on the device. Returns 0 if
*ibctx* is not an ionic device context.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_ctx_get_udma_mask**(3),
**ionic_dv_pd_get_udma_mask**(3),
**ionic_dv_pd_set_udma_mask**(3)

# AUTHORS

Advanced Micro Devices, Inc.
