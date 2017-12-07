---
date: 2013-06-26
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_GET_SRQ_NUM
---

# NAME

ibv_get_srq_num  - return srq number associated with the given shared receive
queue (SRQ)

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_get_srq_num(struct ibv_srq *srq, uint32_t *srq_num);
```

# DESCRIPTION

**ibv_get_srq_num()** return srq number associated with the given shared
receive queue The argument *srq* is an ibv_srq struct, as defined in
<infiniband/verbs.h>. *srq_num* is an output parameter that holds the returned
srq number.


# RETURN VALUE

**ibv_get_srq_num()** returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# SEE ALSO

**ibv_alloc_pd**(3),
**ibv_create_srq_ex**(3),
**ibv_modify_srq**(3)

# AUTHOR

Yishai Hadas <yishaih@mellanox.com>
