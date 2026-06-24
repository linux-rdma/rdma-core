---
layout: page
title: IONIC_DV_PD_SET_SQCMB
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_pd_set_sqcmb - Specify send queue preference for controller memory bar

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

int ionic_dv_pd_set_sqcmb(struct ibv_pd *ibpd, bool enable, bool expdb,
                           bool require);
```

# DESCRIPTION

**ionic_dv_pd_set_sqcmb()** configures the controller memory bar (CMB)
preferences for send queues created under the protection domain *ibpd*.
Send queues created after this call will use the CMB according to the
specified preferences.

When CMB is enabled, the send queue ring buffer is placed in device memory
(the controller memory bar) instead of host memory, which can reduce
doorbell latency.

Express doorbell (expdb) is an additional optimization that further reduces
doorbell overhead when the send queue is placed in CMB.

The *require* flag controls whether creation should fail if the requested
CMB preferences cannot be met. When *require* is false, the driver will
fall back to host memory if CMB is unavailable.

# ARGUMENTS

*ibpd*
:	The protection domain to configure. Must be an ionic protection
	domain.

*enable*
:	Allow the use of the controller memory bar for send queues.

*expdb*
:	Allow the use of express doorbell optimizations. Only meaningful when
	*enable* is true.

*require*
:	Require that the CMB preferences are met. If true and the preferences
	cannot be satisfied, queue creation will fail instead of falling back
	to host memory. Only meaningful when *enable* is true.

# RETURN VALUE

Returns 0 on success, or a positive errno value on failure:

*EPERM*
:	*ibpd* is not an ionic protection domain.

*EINVAL*
:	*require* is true with *expdb* true, but the device does not support
	express doorbell for send queues.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_pd_set_rqcmb**(3),
**ionic_dv_pd_set_udma_mask**(3)

# AUTHORS

Advanced Micro Devices, Inc.
