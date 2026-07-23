---
date: 2026-07-17
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_query_comp_cntr_caps
tagline: Verbs
---

# NAME

**ibv_query_comp_cntr_caps** - Query completion counter capabilities

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_query_comp_cntr_caps(struct ibv_context *context,
                             struct ibv_comp_cntr_caps *caps);
```

# DESCRIPTION

**ibv_query_comp_cntr_caps**() queries the completion counter capabilities
of the RDMA device associated with *context*.

# ARGUMENTS

## ibv_comp_cntr_caps

```c
struct ibv_comp_cntr_caps {
	uint64_t max_value;
	uint32_t max_counters;
	uint32_t supported_qp_attach_ops;
};
```

*max_value*
:	The maximum value a completion counter can hold. A subsequent
	increment that would exceed this value wraps the counter to zero.

*max_counters*
:	The maximum number of completion counters that can be created on
	this device.

*supported_qp_attach_ops*
:	A bitmask of **ibv_qp_attach_comp_cntr_op** values indicating which
	attach operations are supported by the device. See
	**ibv_qp_attach_comp_cntr**(3) for the list of operations.

# RETURN VALUE

**ibv_query_comp_cntr_caps**() returns 0 on success, or the value of errno
on failure (which indicates the failure reason).

# ERRORS

ENOTSUP
:	Completion counters are not supported on this device.

# SEE ALSO

**ibv_create_comp_cntr**(3), **ibv_qp_attach_comp_cntr**(3)

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
