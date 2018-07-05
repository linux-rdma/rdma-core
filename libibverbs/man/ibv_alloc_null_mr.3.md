---
date: 2018-6-1
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_alloc_null_mr
---

# NAME

ibv_alloc_null_mr - allocate a null memory region (MR)

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_mr *ibv_alloc_null_mr(struct ibv_pd *pd);
```


# DESCRIPTION

**ibv_alloc_null_mr()** allocates a null memory region (MR) that is associated with the protection
domain *pd*.

A null MR discards all data written to it, and always returns 0 on
read. It has the maximum length and only the lkey is valid, the MR is not
exposed as an rkey.

A device should implement the null MR in a way that bypasses PCI
transfers, internally discarding or sourcing 0 data. This provides a
way to avoid PCI bus transfers by using a scatter/gather list in
commands if applications do not intend to access the data, or need
data to be 0 filled.

Specifically upon **ibv_post_send()** the device skips PCI read cycles and
upon **ibv_post_recv()** the device skips PCI write cycles which finally
improves performance.

**ibv_dereg_mr()** deregisters the MR.
The use of ibv_rereg_mr() or ibv_bind_mw()
with this MR is invalid.

# RETURN VALUE

**ibv_alloc_null_mr()** returns a pointer to the allocated MR, or NULL if the request fails.

# SEE ALSO

**ibv_reg_mr**(3),
**ibv_dereg_mr**(3),

# AUTHOR

Yonatan Cohen <yonatanc@mellanox.com>

