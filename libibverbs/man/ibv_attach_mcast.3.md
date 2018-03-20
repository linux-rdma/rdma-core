---
date: 2006-10-31
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_ATTACH_MCAST
---

# NAME

ibv_attach_mcast, ibv_detach_mcast - attach and detach a queue pair (QPs)
to/from a multicast group

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid);

int ibv_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid);
```

# DESCRIPTION

**ibv_attach_mcast()** attaches the QP *qp* to the multicast group having MGID
*gid* and MLID *lid*.

**ibv_detach_mcast()** detaches the QP *qp* to the multicast group having MGID
*gid* and MLID *lid*.

# RETURN VALUE

**ibv_attach_mcast()** and **ibv_detach_mcast()** returns 0 on success, or the
value of errno on failure (which indicates the failure reason).

# NOTES

Only QPs of Transport Service Type **IBV_QPT_UD** may be attached to multicast
groups.

If a QP is attached to the same multicast group multiple times, the QP will
still receive a single copy of a multicast message.

In order to receive multicast messages, a join request for the multicast group
must be sent to the subnet administrator (SA), so that the fabric's multicast
routing is configured to deliver messages to the local port.

# SEE ALSO

**ibv_create_qp**(3)

# AUTHOR

Dotan Barak <dotanba@gmail.com>
