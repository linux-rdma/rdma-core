---
layout: page
title: EFADV_QUERY_CQ
section: 3
tagline: Verbs
date: 2025-04-15
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_query_cq - Query EFA specific Completion Queue attributes

# SYNOPSIS

```c
#include <infiniband/efadv.h>

int efadv_query_cq(struct ibv_cq *ibvcq, struct efadv_cq_attr *attr,
                   uint32_t inlen);
```

# DESCRIPTION

**efadv_query_cq()** queries device-specific Completion Queue attributes.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_cq_attr {
	uint64_t comp_mask;
	uint8_t *buffer;
	uint32_t entry_size;
	uint32_t num_entries;
	uint32_t *doorbell;
};
```

*inlen*
:	In: Size of struct efadv_cq_attr.

*comp_mask*
:	Compatibility mask.

*buffer*
:	Completion queue buffer.

*entry_size*
:	Size of each completion queue entry.

*num_entries*
:	Maximal number of entries in the completion queue.

*doorbell*
:	Reverse doorbell used to update the device of polled entries and to
	request notifications. NULL when not in use for this Completion Queue.

# RETURN VALUE

**efadv_query_cq()** returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# SEE ALSO

**efadv**(7)

# NOTES

* Compatibility mask (comp_mask) is an out field and currently has no values.

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
