---
layout: page
title: hbldv_create_cq
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_create_cq - Create a completion queue (CQ) resource

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

struct ibv_cq *hbldv_create_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel, int comp_vector,
			       struct hbldv_cq_attr *cq_attr);
```

# DESCRIPTION

Creates a completion queue (CQ) object with user requested configuration.

# ARGUMENTS

Please see **ibv_create_cq(3)** man page for **context**, **cqe**, **channel**
and **comp_vector**.

## *cq_attr*
:	Input parameters to allocate a CQ resource.

```c
struct hbldv_cq_attr {
	uint32_t port_num;
	enum hbldv_cq_type cq_type;
};
```

*port_num*
:	Port ID(should be non zero).

*cq_type*
:	Type of CQ resource to be allocated:

	HBLDV_CQ_TYPE_QP
		Standard CQ used for completion of an operation for a QP.

	HBLDV_CQ_TYPE_CC
		CQ resource for congestional control.


# RETURN VALUE

Returns a pointer to the created CQ, or NULL if the request fails and errno will
be set.

# SEE ALSO

**hbldv**(7), **hbldv_query_cq**(3), **ibv_create_cq**(3)

# AUTHOR

Zvika Yehudai <zyehudai@habana.ai>
