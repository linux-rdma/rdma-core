---
date: 2020-01-22
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_QUERY_ECE
---

# NAME

ibv_query_ece - query ECE options.

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_query_ece(struct ibv_qp *qp, struct ibv_ece *ece);
```

# DESCRIPTION

**ibv_query_ece()** query ECE options.

Return to the user current ECE state for the QP.

# ARGUMENTS
*qp*
:	The queue pair (QP) associated with the ECE options.

## *ece* Argument
:	The ECE values.

```c
struct ibv_ece {
	uint32_t vendor_id;
	uint32_t options;
	uint32_t comp_mask;
};
```

*vendor_id*
:	Unique identifier of the provider vendor on the network.
	The providers will set IEEE OUI here to distinguish itself
	in non-homogenius network.

*options*
:	Provider specific attributes which are supported.

*comp_mask*
:	Bitmask specifying what fields in the structure are valid.

# RETURN VALUE

**ibv_query_ece()** returns 0 when the call was successful, or the errno value
		    which indicates the failure reason.

*EOPNOTSUPP*
:	libibverbs or provider driver doesn't support the ibv_set_ece() verb.

*EINVAL*
:	In one of the following:
	o The QP is invalid.
	o The ECE options are invalid.

# SEE ALSO

**ibv_set_ece**(3),

# AUTHOR

Leon Romanovsky <leonro@mellanox.com>

