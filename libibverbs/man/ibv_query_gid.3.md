---
date: 2006-10-31
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_QUERY_GID
---

# NAME

ibv_query_gid - query an InfiniBand port's GID table

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_query_gid(struct ibv_context *context,
                  uint8_t port_num,
                  int index,
                  union ibv_gid *gid);
```

# DESCRIPTION

**ibv_query_gid()** returns the GID value in entry *index* of port *port_num*
for device context *context* through the pointer *gid*.

# RETURN VALUE

**ibv_query_gid()** returns 0 on success, and -1 on error.

# SEE ALSO

**ibv_open_device**(3),
**ibv_query_device**(3),
**ibv_query_pkey**(3),
**ibv_query_port**(3)

# AUTHOR

Dotan Barak <dotanba@gmail.com>
