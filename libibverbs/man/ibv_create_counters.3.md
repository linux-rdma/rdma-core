---
date: 2018-04-02
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_create_counters
tagline: Verbs
---

# NAME

**ibv_create_counters**, **ibv_destroy_counters** - Create or destroy a counters handle

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_counters *
ibv_create_counters(struct ibv_context *context,
                    struct ibv_counters_init_attr *init_attr);

int ibv_destroy_counters(struct ibv_counters *counters);
```

# DESCRIPTION

**ibv_create_counters**() creates a new counters handle for the RDMA device
context.

An ibv_counters handle can be attached to a verbs resource (e.g.: QP, WQ, Flow)
statically when these are created.

For example attach an ibv_counters statically to a Flow (struct ibv_flow) during
creation of a new Flow by calling **ibv_create_flow()**.

Counters are cleared upon creation and values will be monotonically increasing.

**ibv_destroy_counters**() releases the counters handle, user should
detach the counters object before destroying it.

# ARGUMENTS

*context*
:	RDMA device context to create the counters on.

*init_attr*
:	Is an ibv_counters_init_attr struct, as defined in verbs.h.

## *init_attr* Argument

```c
struct ibv_counters_init_attr {
	int comp_mask;
};
```

*comp_mask*
:	Bitmask specifying what fields in the structure are valid.

# RETURN VALUE

**ibv_create_counters**() returns a pointer to the allocated ibv_counters
object, or NULL if the request fails (and sets errno to indicate the failure
reason)

**ibv_destroy_counters**() returns 0 on success, or the value of errno on
failure (which indicates the failure reason)

# ERRORS

EOPNOTSUPP
:	**ibv_create_counters**() is not currently supported on this device
	(ENOSYS may sometimes be returned by old versions of libibverbs).

ENOMEM
:	**ibv_create_counters**() could not create ibv_counters object, not enough memory

EINVAL
:	invalid parameter supplied **ibv_destroy_counters**()

# EXAMPLE

An example of use of ibv_counters is shown in **ibv_read_counters**

# SEE ALSO

**ibv_attach_counters_point_flow**, **ibv_read_counters**,
**ibv_create_flow**

# AUTHORS

Raed Salem <raeds@mellanox.com>

Alex Rosenbaum <alexr@mellanox.com>

