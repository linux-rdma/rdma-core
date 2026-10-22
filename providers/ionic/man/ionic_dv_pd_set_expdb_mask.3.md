---
layout: page
title: IONIC_DV_PD_SET_EXPDB_MASK
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_pd_set_expdb_mask - Set express doorbell WQE size mask on a protection domain

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

int ionic_dv_pd_set_expdb_mask(struct ibv_pd *ibpd, uint8_t mask);
```

# DESCRIPTION

**ionic_dv_pd_set_expdb_mask()** sets the express doorbell WQE size mask
on the protection domain *ibpd*. Queues created under this protection
domain will attempt to use express doorbell for WQE sizes enabled by
*mask*, subject to device support.

By default, only 64-byte WQE express doorbell is enabled. Use this
function to enable express doorbell for additional WQE sizes.

The *mask* is a bitwise OR of **IONIC_EXPDB_64**, **IONIC_EXPDB_128**,
**IONIC_EXPDB_256**, and **IONIC_EXPDB_512** constants defined in the
kernel ABI header. Bits not supported by the device are silently ignored.

# ARGUMENTS

*ibpd*
:	The protection domain to configure. Must be an ionic protection
	domain.

*mask*
:	Bitmask of IONIC_EXPDB_* flags indicating desired express doorbell
	WQE sizes.

# RETURN VALUE

Returns 0 on success, or a positive errno value on failure:

*EPERM*
:	*ibpd* is not an ionic protection domain.

# SEE ALSO

**ionicdv**(7),
**ionic_dv_pd_set_sqcmb**(3),
**ionic_dv_pd_set_rqcmb**(3)

# AUTHORS

Advanced Micro Devices, Inc.
