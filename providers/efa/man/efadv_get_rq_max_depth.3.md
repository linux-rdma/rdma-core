---
layout: page
title: EFADV_GET_MAX_RQ_DEPTH
section: 3
tagline: Verbs
date: 2026-02-17
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_get_max_rq_depth - Get EFA receive queue max depth based on receive queue attributes

# SYNOPSIS

```c
#include <infiniband/efadv.h>

int efadv_get_max_rq_depth(struct ibv_context *ibvctx, struct efadv_rq_depth_attr *attr,
			   uint32_t inlen);
```

# DESCRIPTION

**efadv_get_max_rq_depth()** get device-specific receive queue max depth based on RQ attributes.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_rq_depth_attr {
	uint64_t comp_mask;
	uint32_t max_recv_sge;
};
```

*inlen*
:	In: Size of struct efadv_rq_depth_attr.

*comp_mask*
:	Compatibility mask.

*max_recv_sge*
:	Requested max number of scatter/gather (s/g) elements in a WR in the receive queue.

# RETURN VALUE

**efadv_get_max_rq_depth()** returns max receive queue depth on success, or the negative value of errno on failure
(which indicates the failure reason).

# SEE ALSO

**efadv**(7)

# AUTHORS

Yonatan Nachum <ynachum@amazon.com>
