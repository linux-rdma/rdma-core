---
date: 2018-07-16
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_GET_PKEY_INDEX
---

# NAME

ibv_get_pkey_index - obtain the index in the P_Key table of a P_Key

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_get_pkey_index(struct ibv_context *context,
                       uint8_t port_num,
                       __be16 pkey);
```

# DESCRIPTION

Every InfiniBand HCA maintains a P_Key table for each of its ports that is
indexed by an integer and with a P_Key in each element. Certain InfiniBand
data structures that work with P_Keys expect a P_Key index, e.g. **struct
ibv_qp_attr** and **struct ib_mad_addr**. Hence the function
**ibv_get_pkey_index()** that accepts a P_Key in network byte order and that
returns an index in the P_Key table as result.

# RETURN VALUE

**ibv_get_pkey_index()** returns the P_Key index on success, and -1 on error.

# SEE ALSO

**ibv_open_device**(3),
**ibv_query_device**(3),
**ibv_query_gid**(3),
**ibv_query_pkey**(3),
**ibv_query_port**(3)

# AUTHOR

Bart Van Assche <bvanassche@acm.org>
