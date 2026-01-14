---
layout: page
title: EFADV_QUERY_QP_WQS
section: 3
tagline: Verbs
date: 2025-05-14
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_query_qp_wqs - Query EFA specific Queue Pair work queue attributes

# SYNOPSIS

```c
#include <infiniband/efadv.h>

int efadv_query_qp_wqs(struct ibv_qp *ibvqp, struct efadv_wq_attr *sq_attr,
                       struct efadv_wq_attr *rq_attr, uint32_t inlen);
```

# DESCRIPTION

**efadv_query_qp_wqs()** queries device-specific Queue Pair work queue attributes.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_wq_attr {
	uint64_t comp_mask;
	uint8_t *buffer;
	uint32_t entry_size;
	uint32_t num_entries;
	uint32_t *doorbell;
	uint32_t max_batch;
	uint8_t reserved[4];
};
```

*inlen*
:	In: Size of struct efadv_wq_attr.

*comp_mask*
:	Compatibility mask.

*buffer*
:	Queue buffer.

*entry_size*
:	Size of each entry in the queue.

*num_entries*
:	Maximal number of entries in the queue.

*doorbell*
:	Queue doorbell.

*max_batch*
:	Maximum batch size for queue submissions.

# RETURN VALUE

**efadv_query_qp_wqs()** returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# SEE ALSO

**efadv**(7)

# NOTES

* Compatibility mask (comp_mask) is an out field and currently has no values.

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
