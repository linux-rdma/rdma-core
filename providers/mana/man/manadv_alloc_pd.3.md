---
layout: page
title: manadv_alloc_pd
section: 3
tagline: Verbs
---

# NAME
manadv_alloc_pd \- Create a MANA specific PD for the RDMA device context.

# SYNOPSIS"
```c
#include <infiniband/manadv.h>

struct ibv_pd *manadv_alloc_pd(struct ibv_context *context, uint32_t flags);
```

# DESCRIPTION
**manadv_alloc_pd()** allocates a PD for the RDMA device context with additional
creation flags.

# ARGUMENTS
*context*
:	RDMA device context to work on.

*flags*
:	A bitwise OR of the various values described below.

	MANADV_PD_FLAGS_SHORT_PDN:
		allocates a PD with 16 bit PDN.

# RETURN VALUE
returns a pointer to the allocated PD, or NULL if the request fails.

# AUTHORS
Konstantin Taranov <kotaranov@microsoft.com>
