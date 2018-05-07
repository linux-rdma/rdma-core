---
date: 2006-10-31
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_REQ_NOTIFY_CQ
---

# NAME

ibv_req_notify_cq - request completion notification on a completion queue (CQ)

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_req_notify_cq(struct ibv_cq *cq, int solicited_only);
```

# DESCRIPTION

**ibv_req_notify_cq()** requests a completion notification on the completion
queue (CQ) *cq*.

Upon the addition of a new CQ entry (CQE) to *cq*, a completion event will be
added to the completion channel associated with the CQ. If the argument
*solicited_only* is zero, a completion event is generated for any new CQE.  If
*solicited_only* is non-zero, an event is only generated for a new CQE with
that is considered "solicited."  A CQE is solicited if it is a receive
completion for a message with the Solicited Event header bit set, or if the
status is not successful.  All other successful receive completions, or any
successful send completion is unsolicited.

# RETURN VALUE

**ibv_req_notify_cq()** returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# NOTES

The request for notification is "one shot."  Only one completion event will be
generated for each call to **ibv_req_notify_cq()**.

# SEE ALSO

**ibv_create_comp_channel**(3),
**ibv_create_cq**(3),
**ibv_get_cq_event**(3)

# AUTHOR

Dotan Barak <dotanba@gmail.com>
