---
layout: page
title: IONIC_DV_IS_IONIC_PD
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_is_ionic_pd - Test if a protection domain belongs to the ionic provider

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

bool ionic_dv_is_ionic_pd(struct ibv_pd *ibpd);
```

# DESCRIPTION

**ionic_dv_is_ionic_pd()** tests whether the protection domain *ibpd*
belongs to the ionic provider. This can be used by applications that
support multiple RDMA providers to determine whether ionic-specific
direct verbs may be called on the protection domain.

# ARGUMENTS

*ibpd*
:	The protection domain to test.

# RETURN VALUE

Returns true if *ibpd* is an ionic protection domain, false otherwise.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_is_ionic_ctx**(3),
**ionic_dv_is_ionic_cq**(3),
**ionic_dv_is_ionic_qp**(3)

# AUTHORS

Advanced Micro Devices, Inc.
