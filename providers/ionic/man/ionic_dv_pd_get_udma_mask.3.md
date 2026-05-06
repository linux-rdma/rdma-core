---
layout: page
title: IONIC_DV_PD_GET_UDMA_MASK
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_pd_get_udma_mask - Get UDMA pipeline mask of a protection domain

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

uint8_t ionic_dv_pd_get_udma_mask(struct ibv_pd *ibpd);
```

# DESCRIPTION

**ionic_dv_pd_get_udma_mask()** returns the current UDMA pipeline mask
associated with the protection domain or parent domain *ibpd*.

The returned mask indicates which UDMA pipelines are enabled for queues
created under this protection domain. It may have been set by a prior call
to **ionic_dv_pd_set_udma_mask**(3), or it may be the default mask
inherited from the device context.

# ARGUMENTS

*ibpd*
:	The protection domain or parent domain to query. Must be an ionic
	protection domain.

# RETURN VALUE

Returns the UDMA pipeline mask of the protection domain. Returns 0 if
*ibpd* is not an ionic protection domain.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_pd_set_udma_mask**(3),
**ionic_dv_ctx_get_udma_mask**(3),
**ionic_dv_ctx_get_udma_count**(3)

# AUTHORS

Advanced Micro Devices, Inc.
