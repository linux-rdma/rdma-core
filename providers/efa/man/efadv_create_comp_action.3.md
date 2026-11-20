---
layout: page
title: EFADV_CREATE_COMP_ACTION
section: 3
tagline: Verbs
date: 2026-10-18
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_create_mem_comp_action, efadv_destroy_comp_action - Create and
destroy an EFA Completion Action

# SYNOPSIS

```c
#include <infiniband/efadv.h>

struct efadv_mem_comp_action *efadv_create_mem_comp_action(struct ibv_context *context,
							   struct efadv_mem_comp_action_init_attr *attr,
							   uint32_t inlen);

int efadv_destroy_comp_action(struct efadv_comp_action *comp_action);
```

# DESCRIPTION

**efadv_create_mem_comp_action()** creates a memory Completion Action. A
Completion Action is a registered operation that can be attached to work
requests to perform completion actions beyond CQ-based completions. A
memory Completion Action operates on a memory region provided by the
caller.

The returned *action_id* must be communicated out-of-band to the remote
side for use in remote work request completion action setters.

**efadv_destroy_comp_action()** destroys a previously created Completion
Action. Destroying a Completion Action while work requests referencing
its action ID are in flight is racy and may result in completion errors.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_comp_action {
	struct ibv_context *context;
	struct ibv_pd *pd;
	uint32_t handle;
	uint32_t action_id;
};

struct efadv_mem_comp_action {
	struct efadv_comp_action comp_action;
};

enum {
	EFADV_MEM_COMP_ACTION_SET_INITIATOR_VAL,
};

struct efadv_mem_comp_action_init_attr {
	uint64_t comp_mask;
	struct ibv_pd *pd;
	uint32_t flags;
	uint32_t mem_modify_size;
	uint64_t mem_size;
	struct efadv_memory_location comp_mem;
	uint16_t comp_mem_modify_type;
	uint8_t reserved[6];
};
```

*inlen*
:	In: Size of struct efadv_mem_comp_action_init_attr.

*comp_mask*
:	Compatibility mask.

*pd*
:	Protection Domain to associate with the Completion Action. Must
	match the PD of the QP whose completion triggers the action: the
	initiator QP for local actions, the destination QP for remote
	actions.

*flags*
:	Reserved for future use. Must be 0.

*mem_modify_size*
:	Size of each memory modification in bytes: 1, 2, or 4.

*mem_size*
:	Total size of the completion memory region in bytes.

*comp_mem*
:	Memory location for the completion memory region, described by an
	**efadv_memory_location** structure (see
	**efadv_create_comp_cntr**(3) for details on this structure).

*comp_mem_modify_type*
:	The type of memory modification to perform on completion. One of:

	**EFADV_MEM_COMP_ACTION_SET_INITIATOR_VAL** - Write the data value
	to the target memory entry.

## Completion Action struct

*action_id*
:	Unique action identifier assigned by the device. This value must
	be communicated to the initiator side for use in work request
	completion action setters.

# RETURN VALUE

efadv_create_mem_comp_action() returns a pointer to the created
efadv_mem_comp_action, or NULL if the request fails.

efadv_destroy_comp_action() returns 0 on success, or the value of errno
on failure.

# SEE ALSO

**efadv**(7), **efadv_wr_set_comp_action**(3),
**efadv_create_comp_cntr**(3)

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
