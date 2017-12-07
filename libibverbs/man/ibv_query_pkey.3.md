---
date: 2006-10-31
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_QUERY_PKEY
---

# NAME

ibv_query_pkey - query an InfiniBand port's P_Key table

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_query_pkey(struct ibv_context *context,
                   uint8_t port_num,
                   int index,
                   uint16_t *pkey);
```

# DESCRIPTION

**ibv_query_pkey()** returns the P_Key value (in network byte order) in entry
*index* of port *port_num* for device context *context* through the pointer
*pkey*.

# RETURN VALUE

**ibv_query_pkey()** returns 0 on success, and -1 on error.

# SEE ALSO

**ibv_open_device**(3),
**ibv_query_device**(3),
**ibv_query_gid**(3),
**ibv_query_port**(3)

# AUTHOR

Dotan Barak <dotanba@gmail.com>
