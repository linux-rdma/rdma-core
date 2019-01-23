---
layout: page
title: EFADV_CREATE_DRIVER_QP
section: 3
tagline: Verbs
date: 2019-01-23
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME
efadv_create_driver_qp - Create EFA specific Queue Pair
# SYNOPSIS
```c
#include <infiniband/efadv.h>

struct ibv_qp *efadv_create_driver_qp(struct ibv_pd *ibvpd,
                                      struct ibv_qp_init_attr *attr,
                                      uint32_t driver_qp_type);
```

# DESCRIPTION
**efadv_create_driver_qp()**
Create device-specific Queue Pairs.

Scalable Reliable Datagram (SRD) transport provides reliable out-of-order
delivery, transparently utilizing multiple network paths to reduce network tail
latency. Its interface is similar to UD, in particular it supports message size
up to MTU, with error handling extended to support reliable communication.

*driver_qp_type*
:	The type of QP to be created:

	EFADV_QP_DRIVER_TYPE_SRD:
		Create an SRD QP.

# RETURN VALUE
efadv_create_driver_qp() returns a pointer to the created QP, or NULL if the request fails.

# SEE ALSO
**efadv**(7)

# AUTHORS
Gal Pressman <galpress@amazon.com>
