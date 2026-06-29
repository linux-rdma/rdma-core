---
layout: page
title: IONIC_DV_IS_IONIC_CQ
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_is_ionic_cq - Test if a completion queue belongs to the ionic provider

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

bool ionic_dv_is_ionic_cq(struct ibv_cq *ibcq);
```

# DESCRIPTION

**ionic_dv_is_ionic_cq()** tests whether the completion queue *ibcq*
belongs to the ionic provider. This can be used by applications that
support multiple RDMA providers to determine whether ionic-specific
direct verbs may be called on the completion queue.

# ARGUMENTS

*ibcq*
:	The completion queue to test.

# RETURN VALUE

Returns true if *ibcq* is an ionic completion queue, false otherwise.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_is_ionic_ctx**(3),
**ionic_dv_is_ionic_pd**(3),
**ionic_dv_is_ionic_qp**(3)

# AUTHORS

Advanced Micro Devices, Inc.
