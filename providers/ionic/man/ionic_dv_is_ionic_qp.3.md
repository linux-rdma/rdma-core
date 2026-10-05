---
layout: page
title: IONIC_DV_IS_IONIC_QP
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_is_ionic_qp - Test if a queue pair belongs to the ionic provider

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

bool ionic_dv_is_ionic_qp(struct ibv_qp *ibqp);
```

# DESCRIPTION

**ionic_dv_is_ionic_qp()** tests whether the queue pair *ibqp*
belongs to the ionic provider. This can be used by applications that
support multiple RDMA providers to determine whether ionic-specific
direct verbs may be called on the queue pair.

# ARGUMENTS

*ibqp*
:	The queue pair to test.

# RETURN VALUE

Returns true if *ibqp* is an ionic queue pair, false otherwise.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_is_ionic_ctx**(3),
**ionic_dv_is_ionic_pd**(3),
**ionic_dv_is_ionic_cq**(3)

# AUTHORS

Advanced Micro Devices, Inc.
