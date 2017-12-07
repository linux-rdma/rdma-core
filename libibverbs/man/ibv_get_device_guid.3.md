---
date: 2006-10-31
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_GET_DEVICE_GUID
---

# NAME

ibv_get_device_guid - get an RDMA device's GUID

# SYNOPSIS

```c
#include <infiniband/verbs.h>

uint64_t ibv_get_device_guid(struct ibv_device *device);
```

# DESCRIPTION

**ibv_get_device_name()** returns the Global Unique IDentifier (GUID) of the
RDMA device *device*.

# RETURN VALUE

**ibv_get_device_guid()** returns the GUID of the device in network byte
order.

# SEE ALSO

**ibv_get_device_list**(3),
**ibv_get_device_name**(3),
**ibv_open_device**(3)

# AUTHOR

Dotan Barak <dotanba@gmail.com>
