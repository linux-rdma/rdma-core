---
layout: page
title: EFADV_QUERY_DEVICE
section: 3
tagline: Verbs
date: 2019-04-22
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_query_device - Query device capabilities

# SYNOPSIS

```c
#include <infiniband/efadv.h>

int efadv_query_device(struct ibv_context *ibvctx,
		       struct efadv_device_attr *attr,
		       uint32_t inlen);
```

# DESCRIPTION

**efadv_query_device()** Queries EFA device specific attributes.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_device_attr {
	uint64_t comp_mask;
	uint32_t max_sq_wr;
	uint32_t max_rq_wr;
	uint16_t max_sq_sge;
	uint16_t max_rq_sge;
	uint16_t inline_buf_size;
	uint8_t reserved[2];
	uint32_t device_caps;
	uint32_t max_rdma_size;
};
```

*inlen*
:	In: Size of struct efadv_device_attr.

*comp_mask*
:	Compatibility mask.

*max_sq_wr*
:	Maximum Send Queue (SQ) Work Requests (WRs).

*max_rq_wr*
:	Maximum Receive Queue (RQ) Work Requests (WRs).

*max_sq_sge*
:	Maximum Send Queue (SQ) Scatter Gather Elements (SGEs).

*max_rq_sge*
:	Maximum Receive Queue (RQ) Scatter Gather Elements (SGEs).

*inline_buf_size*
:	Maximum inline buffer size.

*device_caps*
:	Bitmask of device capabilities:

	EFADV_DEVICE_ATTR_CAPS_RDMA_READ:
		RDMA read is supported.

*max_rdma_size*
:	Maximum RDMA transfer size in bytes.

# RETURN VALUE

**efadv_query_device()** returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# SEE ALSO

**efadv**(7)

# NOTES

* Compatibility mask (comp_mask) is an out field and currently has no values.

# AUTHORS

Gal Pressman <galpress@amazon.com>
