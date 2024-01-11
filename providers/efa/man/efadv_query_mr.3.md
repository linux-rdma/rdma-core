---
layout: page
title: EFADV_QUERY_MR
section: 3
tagline: Verbs
date: 2023-11-13
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_query_mr - Query EFA specific Memory Region attributes

# SYNOPSIS

```c
#include <infiniband/efadv.h>

int efadv_query_mr(struct ibv_mr *ibvmr, struct efadv_mr_attr *attr, uint32_t inlen);
```

# DESCRIPTION

**efadv_query_mr()** queries device-specific Memory Region attributes.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_mr_attr {
	uint64_t comp_mask;
	uint16_t ic_id_validity;
	uint16_t recv_ic_id;
	uint16_t rdma_read_ic_id;
	uint16_t rdma_recv_ic_id;
};
```

*inlen*
:	In: Size of struct efadv_mr_attr.

*comp_mask*
:	Compatibility mask.

*ic_id_validity*
:	Validity mask of interconnect id fields:

	EFADV_MR_ATTR_VALIDITY_RECV_IC_ID:
		recv_ic_id has a valid value.

	EFADV_MR_ATTR_VALIDITY_RDMA_READ_IC_ID:
		rdma_read_ic_id has a valid value.

	EFADV_MR_ATTR_VALIDITY_RDMA_RECV_IC_ID:
		rdma_recv_ic_id has a valid value.

*recv_ic_id*
:	Physical interconnect used by the device to reach the MR for receive operation.

*rdma_read_ic_id*
:	Physical interconnect used by the device to reach the MR for RDMA read operation.

*rdma_recv_ic_id*
:	Physical interconnect used by the device to reach the MR for RDMA write receive.

# RETURN VALUE

**efadv_query_mr()** returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# SEE ALSO

**efadv**(7)

# NOTES

* Compatibility mask (comp_mask) is an out field and currently has no values.

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
