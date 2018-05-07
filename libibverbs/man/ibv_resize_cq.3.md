---
date: 2006-10-31
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_RESIZE_CQ
---

# NAME

ibv_resize_cq - resize a completion queue (CQ)

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_resize_cq(struct ibv_cq *cq, int cqe);
```

# DESCRIPTION

**ibv_resize_cq()** resizes the completion queue (CQ) *cq* to have at least
*cqe* entries. *cqe* must be at least the number of unpolled entries in the CQ
*cq*. If *cqe* is a valid value less than the current CQ size,
**ibv_resize_cq()** may not do anything, since this function is only
guaranteed to resize the CQ to a size at least as big as the requested size.

# RETURN VALUE

**ibv_resize_cq()** returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# NOTES

**ibv_resize_cq()** may assign a CQ size greater than or equal to the
requested size. The cqe member of *cq* will be updated to the actual size.

# SEE ALSO

**ibv_create_cq**(3),
**ibv_destroy_cq**(3)

# AUTHOR

Dotan Barak <dotanba@gmail.com>
