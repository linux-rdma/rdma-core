---
layout: page
title: EFADV_CREATE_QP_EX
section: 3
tagline: Verbs
date: 2019-08-06
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_create_qp_ex - Create EFA specific extended Queue Pair

# SYNOPSIS

```c
#include <infiniband/efadv.h>

struct ibv_qp *efadv_create_qp_ex(struct ibv_context *ibvctx,
				  struct ibv_qp_init_attr_ex *attr_ex,
				  struct efadv_qp_init_attr *efa_attr,
				  uint32_t inlen);
```

# DESCRIPTION

**efadv_create_qp_ex()** creates device-specific extended Queue Pair.

The argument attr_ex is an ibv_qp_init_attr_ex struct,
as defined in <infiniband/verbs.h>.

Use ibv_qp_to_qp_ex() to get the ibv_qp_ex for accessing the send ops
iterator interface, when QP create attr IBV_QP_INIT_ATTR_SEND_OPS_FLAGS is used.

Scalable Reliable Datagram (SRD) transport provides reliable out-of-order
delivery, transparently utilizing multiple network paths to reduce network tail
latency. Its interface is similar to UD, in particular it supports message size
up to MTU, with error handling extended to support reliable communication.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_qp_init_attr {
	uint64_t comp_mask;
	uint32_t driver_qp_type;
	uint8_t reserved[4];
};
```

*inlen*
:	In: Size of struct efadv_qp_init_attr.

*comp_mask*
:	Compatibility mask.

*driver_qp_type*
:	The type of QP to be created:

	EFADV_QP_DRIVER_TYPE_SRD:
		Create an SRD QP.

# RETURN VALUE

efadv_create_qp_ex() returns a pointer to the created QP, or NULL if the request fails.

# SEE ALSO

**efadv**(7), **ibv_create_qp_ex**(3)

# AUTHORS

Gal Pressman <galpress@amazon.com>
Daniel Kranzdorf <dkkranzd@amazon.com>
