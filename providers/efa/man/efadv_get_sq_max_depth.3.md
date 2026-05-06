---
layout: page
title: EFADV_GET_MAX_SQ_DEPTH
section: 3
tagline: Verbs
date: 2026-02-17
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_get_max_sq_depth - Get EFA send queue max depth based on send queue attributes

# SYNOPSIS

```c
#include <infiniband/efadv.h>

int efadv_get_max_sq_depth(struct ibv_context *ibvctx, struct efadv_sq_depth_attr *attr,
			   uint32_t inlen);
```

# DESCRIPTION

**efadv_get_max_sq_depth()** get device-specific send queue max depth based on SQ attributes.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_sq_depth_attr {
	uint64_t comp_mask;
	uint32_t flags;
	uint32_t max_send_sge;
	uint32_t max_rdma_sge;
	uint32_t max_inline_data;
};
```

*inlen*
:	In: Size of struct efadv_sq_depth_attr.

*comp_mask*
:	Compatibility mask.

*flags*
:       A bitwise OR of the values described below.

	EFADV_SQ_DEPTH_ATTR_INLINE_WRITE:
		Inline RDMA write operation support is required.

*max_send_sge*
:	Requested max number of scatter/gather (s/g) elements in a send WR in the send queue.

*max_rdma_sge*
:	Requested max number of scatter/gather (s/g) elements in a RDMA WR in the send queue.

*max_inline_data*
:	Requested max number of data (bytes) that can be posted inline to the send queue.

# RETURN VALUE

**efadv_get_max_sq_depth()** returns max send queue depth on success, or the negative value of errno on failure
(which indicates the failure reason).

# SEE ALSO

**efadv**(7)

# AUTHORS

Yonatan Nachum <ynachum@amazon.com>
