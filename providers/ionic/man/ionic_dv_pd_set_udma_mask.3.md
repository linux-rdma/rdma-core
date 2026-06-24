---
layout: page
title: IONIC_DV_PD_SET_UDMA_MASK
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_pd_set_udma_mask - Restrict UDMA pipeline IDs of a protection domain

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

int ionic_dv_pd_set_udma_mask(struct ibv_pd *ibpd, uint8_t udma_mask);
```

# DESCRIPTION

**ionic_dv_pd_set_udma_mask()** restricts the UDMA pipelines available for
queues created under the protection domain or parent domain *ibpd*. Queues
created after this call will be assigned to one of the pipelines enabled by
*udma_mask*.

The *udma_mask* must be a subset of the device's available UDMA pipelines,
as returned by **ionic_dv_ctx_get_udma_mask**(3).

Changing the UDMA mask of a protection domain has no effect on previously
created queues.

The recommended usage pattern is:

1. Create a protection domain with **ibv_alloc_pd**(3).
2. Create parent domains of that PD for each desired UDMA mask using
   **ibv_alloc_parent_domain**(3).
3. Set the desired UDMA mask on each parent domain with this function.
4. Create queues associated with the parent domain that has the desired
   UDMA mask.

An alternative usage is to create a single PD and change its UDMA mask
before creating each queue.

# ARGUMENTS

*ibpd*
:	The protection domain or parent domain to modify. Must be an ionic
	protection domain.

*udma_mask*
:	A bitmask of UDMA pipeline IDs to enable. Must be a subset of the
	mask returned by **ionic_dv_ctx_get_udma_mask**(3).

# RETURN VALUE

Returns 0 on success, or a positive errno value on failure:

*EPERM*
:	*ibpd* is not an ionic protection domain.

*EINVAL*
:	*udma_mask* contains bits not present in the device's UDMA mask.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_pd_get_udma_mask**(3),
**ionic_dv_ctx_get_udma_mask**(3),
**ionic_dv_ctx_get_udma_count**(3),
**ibv_alloc_pd**(3),
**ibv_alloc_parent_domain**(3)

# AUTHORS

Advanced Micro Devices, Inc.
