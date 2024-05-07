---
layout: page
title: hbldv_query_device
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_query_device - Query an RDMA device

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

int hbldv_query_device(struct ibv_context *context, struct hbldv_device_attr *attr);
```

# DESCRIPTION

Query an RDMA device of hbl provider.

# ARGUMENTS

*context*
:	RDMA device context to work on.

## *attr*
:	Stores the provider specific device attributes.

```c
struct hbldv_device_attr {
	uint64_t caps;
	uint64_t ports_mask;
};
```

*caps*
:	Bitmask of device capabilities:

	HBLDV_DEVICE_ATTR_CAP_CC:
		Congestion control is supported.

*ports_mask*
:	Mask of the relevant ports for this context (should be 1-based).

# RETURN VALUE

Returns 0 on success, or the value of errno on failure.

# SEE ALSO

**hbldv**(7), **hbldv_query_port**(3)

# AUTHOR

Omer Shpigelman <oshpigelman@habana.ai>
