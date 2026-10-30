---
layout: page
title: IONIC_DV_IS_IONIC_CTX
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_is_ionic_ctx - Test if a device context belongs to the ionic provider

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

bool ionic_dv_is_ionic_ctx(struct ibv_context *ibctx);
```

# DESCRIPTION

**ionic_dv_is_ionic_ctx()** tests whether the device context *ibctx*
belongs to the ionic provider. This can be used by applications that
support multiple RDMA providers to determine whether ionic-specific
direct verbs may be called on the context.

# ARGUMENTS

*ibctx*
:	The device context to test.

# RETURN VALUE

Returns true if *ibctx* is an ionic device context, false otherwise.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_is_ionic_pd**(3),
**ionic_dv_is_ionic_cq**(3),
**ionic_dv_is_ionic_qp**(3)

# AUTHORS

Advanced Micro Devices, Inc.
