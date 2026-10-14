---
date: 2026-08-08
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_create_ah_ex
---

# NAME

ibv_create_ah_ex - create an extended address handle

ibv_ah_to_ah_ex - get the extended address handle of an address handle

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_ah *ibv_create_ah_ex(struct ibv_pd *pd,
                                struct ibv_ah_attr_ex *attr);

struct ibv_ah_ex *ibv_ah_to_ah_ex(struct ibv_ah *ah);
```

# DESCRIPTION

An Ultra Ethernet peer is identified by both network information and
transport information. A plain address handle carries only the former, so an
extended address handle adds the peer's queue pair number, making the handle
sufficient on its own to name a destination.

This matters because an RU queue pair is not connected: it reaches every
peer in its job, and each work request names where it is going. See
**ibv_uet**(7).

**ibv_create_ah_ex()** creates an extended address handle in the protection
domain *pd* from the attributes in *attr*. It returns the base
*struct ibv_ah*, which is destroyed with **ibv_destroy_ah**(3) in the usual
way.

**ibv_ah_to_ah_ex()** converts a base address handle returned by
**ibv_create_ah_ex()** into the enclosing *struct ibv_ah_ex*, giving access
to *remote_qpn*. Passing an address handle that was not created by
**ibv_create_ah_ex()** is undefined.

An extended address handle is named on a work request with
**ibv_wr_set_ru_addr**(), or in the *ah* member of the *ru* or *ru_rdma* arm
of *struct ibv_send_wr*. Alternatively a peer may be named by job address
table index; see **ibv_insert_addr**(3).

# ARGUMENTS

## attr

```c
struct ibv_ah_attr_ex {
	struct ibv_ah_attr	ah_attr;
	uint32_t		remote_qpn;
};
```

*ah_attr*
:	The network address vector, as for **ibv_create_ah**(3). For Ultra
	Ethernet the GID selected by *ah_attr.grh.sgid_index* determines the
	address family used on the wire; see **ibv_query_gid_ex**(3).

*remote_qpn*
:	The peer's queue pair number. For an RU queue pair this value is
	structured, encoding the peer's PIDonFEP and Resource Index; see
	**ibv_uet**(7).

# RETURN VALUE

**ibv_create_ah_ex()** returns a pointer to the base address handle, or NULL
on failure with *errno* set.

**ibv_ah_to_ah_ex()** returns the enclosing extended address handle.

# NOTES

Extended address handles are supported only by devices reporting
*IBV_DEVICE_RU* in *device_cap_flags_ex*; on other devices
**ibv_create_ah_ex()** fails with EOPNOTSUPP.

# SEE ALSO

**ibv_create_ah**(3),
**ibv_destroy_ah**(3),
**ibv_insert_addr**(3),
**ibv_wr_post**(3),
**ibv_post_send**(3),
**ibv_query_gid_ex**(3),
**ibv_uet**(7)

# AUTHOR

Eric Davis <eric.davis@broadcom.com>
