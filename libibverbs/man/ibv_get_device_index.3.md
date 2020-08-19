---
date: ' 2020-04-22'
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_GET_DEVICE_INDEX
---

# NAME

ibv_get_device_index - get an RDMA device index

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_get_device_index(struct ibv_device *device);
```

# DESCRIPTION

**ibv_get_device_index()** returns stable IB device index as it is assigned by the kernel.

# RETURN VALUE

**ibv_get_device_index()** returns an index, or -1 if the kernel doesn't support device indexes.

# SEE ALSO

**ibv_get_device_name**(3),
**ibv_get_device_guid**(3),
**ibv_get_device_list**(3),
**ibv_open_device**(3)

# AUTHOR

Leon Romanovsky <leonro@mellanox.com>
