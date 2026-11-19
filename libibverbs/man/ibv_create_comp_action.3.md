---
date: 2026-11-18
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_create_comp_action
tagline: Verbs
---

# NAME

**ibv_create_mem_comp_action**, **ibv_destroy_comp_action** - Create or
destroy a completion action

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_mem_comp_action *
ibv_create_mem_comp_action(struct ibv_pd *pd,
                           struct ibv_mem_comp_action_init_attr *attr);

int ibv_destroy_comp_action(struct ibv_comp_action *comp_action);
```

# DESCRIPTION

Completion actions let an application observe the completion of specific work
requests without polling a completion queue. A completion action is an
operation registered with the device. A work request names the action through
its action ID, and the device performs the action when the work request
completes, either at the initiator or at the target. This is useful mainly for
transports that complete work requests out of order, where a completion count
alone does not tell which requests have completed.

**ibv_create_mem_comp_action**() creates a memory completion action on the
protection domain *pd*. A memory completion action modifies application memory
described by *attr*. The returned object holds the action ID to be used in work
requests. The maximum number of completion actions a device supports is
reported by **ibv_query_comp_action_caps**(3).

The action ID must be communicated out-of-band to any remote peer that names
the action in its work requests.

**ibv_destroy_comp_action**() releases all resources associated with the
completion action *comp_action*. For a memory completion action, pass the
embedded *comp_action* member. Destroying an action while work requests that
name it are in flight is racy, and those work requests may complete with an
error.

# ARGUMENTS

## ibv_comp_action

```c
struct ibv_comp_action {
	struct ibv_context *context;
	struct ibv_pd *pd;
	uint32_t handle;
	uint32_t action_id;
};

struct ibv_mem_comp_action {
	struct ibv_comp_action comp_action;
};
```

*context*
:	Device context associated with the completion action.

*pd*
:	Protection domain associated with the completion action.

*handle*
:	Kernel object handle for the completion action.

*action_id*
:	Identifier of the action assigned by the device, to be passed to the
	completion action setters described in **ibv_wr_post**(3).

## ibv_mem_comp_action_init_attr

```c
enum ibv_mem_comp_action_modify_type {
	IBV_MEM_COMP_ACTION_SET_INITIATOR_OFF_VAL,
};

struct ibv_mem_comp_action_init_attr {
	uint32_t comp_mask;
	uint32_t flags;
	struct ibv_buf *buf;
	uint64_t offset;
	uint64_t length;
	uint32_t modify_size;
	enum ibv_mem_comp_action_modify_type modify_type;
};
```

*comp_mask*
:	Compatibility mask.

*flags*
:	Reserved for future use, for now must be 0.

*buf*
:	Buffer holding the target memory, obtained from **ibv_alloc_buf**(3) or
	**ibv_alloc_user_buf**(3). The buffer must belong to *pd*.

*offset*
:	Start of the target memory within *buf*. The target memory must be
	aligned to *modify_size*.

*length*
:	Length of the target memory in bytes. The range starting at *offset*
	must lie within *buf*. Devices may require *length* to equal
	*modify_size*.

*modify_size*
:	Size of each memory modification in bytes: 1, 2, or 4.

*modify_type*
:	The memory modification performed when the action is triggered. The
	values are described below.

**IBV_MEM_COMP_ACTION_SET_INITIATOR_OFF_VAL**
:	Write a value supplied by the initiator's work request to the target
	memory. The 64-bit data operand of the work request is interpreted as
	follows. The low 32 bits hold the value to write; its least significant
	*modify_size* bytes are written. The high 32 bits hold the byte offset
	in the target memory that will be set. The offset plus *modify_size*
	must not exceed *length*; otherwise the device completes the work
	request in error.

The protection domain of the action must match the protection domain of the QP
whose completion triggers it: the initiator QP for local actions and the
destination QP for remote actions.

# RETURN VALUE

**ibv_create_mem_comp_action**() returns a pointer to the allocated
ibv_mem_comp_action object, or NULL if the request fails (and sets errno to
indicate the failure reason).

**ibv_destroy_comp_action**() returns 0 on success, or the value of errno on
failure (which indicates the failure reason).

# ERRORS

EOPNOTSUPP
:	Completion actions, or the requested action configuration, are not
	supported on this device.

ENOMEM
:	Not enough resources to create the completion action.

EINVAL
:	Invalid argument(s) passed.

# SEE ALSO

**ibv_query_comp_action_caps**(3), **ibv_wr_post**(3),
**ibv_create_qp_ex**(3), **ibv_alloc_buf**(3), **ibv_alloc_user_buf**(3),
**ibv_create_comp_cntr**(3)

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
