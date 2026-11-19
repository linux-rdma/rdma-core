---
date: 2026-11-18
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_query_comp_action_caps
tagline: Verbs
---

# NAME

**ibv_query_comp_action_caps** - Query completion action capabilities

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_query_comp_action_caps(struct ibv_context *context,
                               struct ibv_comp_action_caps *caps);
```

# DESCRIPTION

**ibv_query_comp_action_caps**() queries the completion action capabilities
of the RDMA device associated with *context*.

# ARGUMENTS

## ibv_comp_action_caps

```c
enum ibv_comp_action_op {
	IBV_COMP_ACTION_OP_SEND				= 1 << 0,
	IBV_COMP_ACTION_OP_RECV				= 1 << 1,
	IBV_COMP_ACTION_OP_RDMA_READ			= 1 << 2,
	IBV_COMP_ACTION_OP_REMOTE_RDMA_READ		= 1 << 3,
	IBV_COMP_ACTION_OP_RDMA_WRITE			= 1 << 4,
	IBV_COMP_ACTION_OP_REMOTE_RDMA_WRITE		= 1 << 5,
	IBV_COMP_ACTION_OP_REMOTE_RDMA_WRITE_IMM	= 1 << 6,
};

struct ibv_comp_action_caps {
	uint32_t max_actions;
	uint32_t supported_ops;
};
```

*max_actions*
:	The maximum number of completion actions of all types that can be
	created on this device.

*supported_ops*
:	A bitmask of **ibv_comp_action_op** values indicating which completion
	events can trigger completion actions. The values are described below.

**IBV_COMP_ACTION_OP_SEND**
:	Send completion.

**IBV_COMP_ACTION_OP_RECV**
:	Receive completion.

**IBV_COMP_ACTION_OP_RDMA_READ**
:	RDMA read initiator completion.

**IBV_COMP_ACTION_OP_REMOTE_RDMA_READ**
:	RDMA read target (responder) completion.

**IBV_COMP_ACTION_OP_RDMA_WRITE**
:	RDMA write initiator completion.

**IBV_COMP_ACTION_OP_REMOTE_RDMA_WRITE**
:	RDMA write target completion.

**IBV_COMP_ACTION_OP_REMOTE_RDMA_WRITE_IMM**
:	RDMA write with immediate target completion.

# RETURN VALUE

**ibv_query_comp_action_caps**() returns 0 on success, or the value of errno
on failure (which indicates the failure reason).

# ERRORS

EOPNOTSUPP
:	Completion actions are not supported on this device.

# SEE ALSO

**ibv_create_comp_action**(3), **ibv_wr_post**(3)

# AUTHORS

Michael Margolin <mrgolin@amazon.com>
