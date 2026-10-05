---
layout: page
title: IONIC_DV_CREATE_CQ_EX
section: 3
tagline: Verbs
date: 2025-06-23
header: "Ionic Programmer's Manual"
footer: ionic
---

# NAME

ionic_dv_create_cq_ex - Create a completion queue with vendor-specific attributes

# SYNOPSIS

```c
#include <infiniband/ionic_dv.h>

struct ibv_cq_ex *ionic_dv_create_cq_ex(struct ibv_context *ibctx,
                    struct ibv_cq_init_attr_ex *ex,
                    struct ionic_cq_init_attr_ex *ionic_ex);
```

# DESCRIPTION

**ionic_dv_create_cq_ex()** creates a completion queue with both standard
IBV attributes and ionic vendor-specific attributes.

The *ionic_ex* parameter may be NULL, in which case the function behaves
identically to **ibv_create_cq_ex**. When provided, *ionic_ex* allows
specifying additional ionic-specific options:

## ionic_cq_init_attr_ex

*comp_mask*
:	Bitmask of **enum ionic_cq_init_attr_mask** values indicating
	which fields are valid.

*flags*
:	Bitmask of **enum ionic_cq_init_attr_flags** values. Only valid
	when *comp_mask* includes **IONIC_CQ_INIT_ATTR_MASK_FLAGS**.

## Flags

**IONIC_CQ_INIT_ATTR_CCQE**
:	Enable compact CQE mode. When set, the CQ may be created with
	zero entries and CQEs are encoded in a compact format.

# ARGUMENTS

*ibctx*
:	The device context to create the CQ on. Must be an ionic device
	context.

*ex*
:	Standard IBV CQ creation attributes.

*ionic_ex*
:	Ionic vendor-specific CQ creation attributes. May be NULL.

# RETURN VALUE

Returns a pointer to the created **ibv_cq_ex** on success, or NULL on
failure with errno set:

*EPERM*
:	*ibctx* is not an ionic device context.

*ENOTSUP*
:	Unsupported flags or comp_mask bits were specified.

*EINVAL*
:	Invalid CQ size or parameters.

# SEE ALSO

**ionicdv**(7),
**ibv_create_cq_ex**(3)

# AUTHORS

Advanced Micro Devices, Inc.
