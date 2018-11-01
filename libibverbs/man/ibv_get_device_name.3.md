---
date: ' 2006-10-31'
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_GET_DEVICE_NAME
---

# NAME

ibv_get_device_name - get an RDMA device's name

# SYNOPSIS

```c
#include <infiniband/verbs.h>

const char *ibv_get_device_name(struct ibv_device *device);
```

# DESCRIPTION

**ibv_get_device_name()** returns a human-readable name associated with the
RDMA device *device*.

# RETURN VALUE

**ibv_get_device_name()** returns a pointer to the device name, or NULL if the
request fails.

# SEE ALSO

**ibv_get_device_guid**(3),
**ibv_get_device_list**(3),
**ibv_open_device**(3)

# AUTHOR

Dotan Barak <dotanba@gmail.com>
