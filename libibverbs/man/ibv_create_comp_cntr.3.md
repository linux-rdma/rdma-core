---
date: 2026-02-09
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_create_comp_cntr
tagline: Verbs
---

# NAME

**ibv_create_comp_cntr**, **ibv_destroy_comp_cntr** - Create or destroy a
completion counter

**ibv_set_comp_cntr**, **ibv_set_err_comp_cntr** - Set the value of a
completion or error counter

**ibv_inc_comp_cntr**, **ibv_inc_err_comp_cntr** - Increment a completion or
error counter

**ibv_read_comp_cntr**, **ibv_read_err_comp_cntr** - Read the value of a
completion or error counter

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_comp_cntr *ibv_create_comp_cntr(struct ibv_context *context,
                                           struct ibv_comp_cntr_init_attr *cc_attr);

int ibv_destroy_comp_cntr(struct ibv_comp_cntr *comp_cntr);

int ibv_set_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t value);
int ibv_set_err_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t value);
int ibv_inc_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t amount);
int ibv_inc_err_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t amount);
int ibv_read_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t *value);
int ibv_read_err_comp_cntr(struct ibv_comp_cntr *comp_cntr, uint64_t *value);
```

# DESCRIPTION

Completion counters provide a lightweight completion mechanism as an
alternative or extension to completion queues (CQs). Rather than generating
individual completion queue entries, a completion counter tracks the aggregate
number of completed operations. This makes them well suited for applications
that need to know how many requests have completed without requiring
per-request details, such as credit based flow control or tracking responses
from remote peers.

Each completion counter maintains two distinct 64-bit values: a completion
count that is incremented on successful completions, and an error count that
is incremented when operations complete in error.

**ibv_create_comp_cntr**() allocates a new completion counter for the RDMA
device context *context*. The properties of the counter are defined by
*cc_attr*. The maximum number of completion counters a device supports is
reported by the *max_comp_cntr* field of **ibv_device_attr_ex**.

**ibv_destroy_comp_cntr**() releases all resources associated with the
completion counter *comp_cntr*. The counter must not be attached to any QP
when destroyed.

**ibv_set_comp_cntr**() sets the completion count of *comp_cntr* to *value*.

**ibv_set_err_comp_cntr**() sets the error count of *comp_cntr* to *value*.

**ibv_inc_comp_cntr**() increments the completion count of *comp_cntr* by
*amount*.

**ibv_inc_err_comp_cntr**() increments the error count of *comp_cntr* by
*amount*.

**ibv_read_comp_cntr**() reads the current completion count of *comp_cntr*
into *value*.

**ibv_read_err_comp_cntr**() reads the current error count of *comp_cntr*
into *value*.

# ARGUMENTS

## ibv_comp_cntr

```c
struct ibv_comp_cntr {
	struct ibv_context *context;
	uint32_t handle;
	uint64_t comp_count_max_value;
	uint64_t err_count_max_value;
};
```

*context*
:	Device context associated with the completion counter.

*handle*
:	Kernel object handle for the completion counter.

*comp_count_max_value*
:	The maximum value the completion count can hold. A subsequent
	increment that would exceed this value wraps the counter to zero.

*err_count_max_value*
:	The maximum value the error count can hold. A subsequent increment
	that would exceed this value wraps the counter to zero.

## ibv_comp_cntr_init_attr

```c
enum ibv_comp_cntr_type {
	IBV_COMP_CNTR_TYPE_WRS,
	IBV_COMP_CNTR_TYPE_BYTES,
};

struct ibv_comp_cntr_init_attr {
	uint32_t comp_mask;
	enum ibv_comp_cntr_type type;
	uint32_t flags;
};
```

*comp_mask*
:	Bitmask specifying what fields in the structure are valid.

*type*
:	The counting mode for the completion counter. Not all devices support
	all modes.
	**IBV_COMP_CNTR_TYPE_WRS** counts completed work requests (default).
	**IBV_COMP_CNTR_TYPE_BYTES** counts completed bytes.

*flags*
:	Reserved for future use, for now must be 0.

# RETURN VALUE

**ibv_create_comp_cntr**() returns a pointer to the allocated ibv_comp_cntr
object, or NULL if the request fails (and sets errno to indicate the failure
reason).

**ibv_destroy_comp_cntr**(), **ibv_set_comp_cntr**(),
**ibv_set_err_comp_cntr**(), **ibv_inc_comp_cntr**(),
**ibv_inc_err_comp_cntr**(), **ibv_read_comp_cntr**(), and
**ibv_read_err_comp_cntr**() return 0 on success, or the value of errno on
failure (which indicates the failure reason).

# ERRORS

ENOTSUP
:	Completion counters are not supported on this device, or the
	requested operation is not supported for the given counter
	configuration.

ENOMEM
:	Not enough resources to create the completion counter.

EINVAL
:	Invalid argument(s) passed.

EBUSY
:	The completion counter is still attached to a QP
	(**ibv_destroy_comp_cntr**() only).

# NOTES

Counter values must only be updated using **ibv_set_comp_cntr**(),
**ibv_set_err_comp_cntr**(), **ibv_inc_comp_cntr**(), or
**ibv_inc_err_comp_cntr**().

Updates made to counter values (e.g. via **ibv_set_comp_cntr**() or
**ibv_inc_comp_cntr**()) may not be immediately visible when reading the
counter via **ibv_read_comp_cntr**() or **ibv_read_err_comp_cntr**(). A small
delay may occur between the update and the observed value. However, the final
updated value will eventually be reflected.

Applications should ensure that the counter value is stable before calling
**ibv_set_comp_cntr**() or **ibv_set_err_comp_cntr**(). Otherwise, concurrent
updates may be lost.

# SEE ALSO

**ibv_qp_attach_comp_cntr**(3), **efadv_create_comp_cntr**(3),
**ibv_create_cq**(3), **ibv_create_cq_ex**(3), **ibv_create_qp**(3)

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
