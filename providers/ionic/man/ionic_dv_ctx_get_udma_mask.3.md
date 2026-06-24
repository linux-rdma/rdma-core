---
layout: page
title: IONIC_DV_CTX_GET_UDMA_MASK
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_ctx_get_udma_mask - Get mask of UDMA pipeline IDs

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

uint8_t ionic_dv_ctx_get_udma_mask(struct ibv_context *ibctx);
```

# DESCRIPTION

**ionic_dv_ctx_get_udma_mask()** returns a bitmask of all UDMA pipeline IDs
available on the ionic device associated with *ibctx*. Each set bit
represents an available pipeline.

The returned mask represents the full set of pipelines supported by the
device. A protection domain's UDMA mask (set via
**ionic_dv_pd_set_udma_mask**(3)) must be a subset of this device mask.

# ARGUMENTS

*ibctx*
:	The device context to query. Must be an ionic device context.

# RETURN VALUE

Returns a bitmask of available UDMA pipeline IDs. Returns 0 if *ibctx* is
not an ionic device context.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_ctx_get_udma_count**(3),
**ionic_dv_pd_get_udma_mask**(3),
**ionic_dv_pd_set_udma_mask**(3)

# AUTHORS

Advanced Micro Devices, Inc.
