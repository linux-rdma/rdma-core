---
date: 2006-10-31
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_GET_DEVICE_LIST
---

# NAME

ibv_get_device_list, ibv_free_device_list - get and release list of available
RDMA devices

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_device **ibv_get_device_list(int *num_devices);

void ibv_free_device_list(struct ibv_device **list);
```

# DESCRIPTION

**ibv_get_device_list()** returns a NULL-terminated array of RDMA devices
currently available. The argument *num_devices* is optional; if not NULL, it
is set to the number of devices returned in the array.

**ibv_free_device_list()** frees the array of devices *list* returned by
**ibv_get_device_list()**.

# RETURN VALUE

**ibv_get_device_list()** returns the array of available RDMA devices, or sets
*errno* and returns NULL if the request fails. If no devices are found then
*num_devices* is set to 0, and non-NULL is returned.

**ibv_free_device_list()** returns no value.

# ERRORS

**EPERM**
:	Permission denied.

**ENOSYS**
:	No kernel support for RDMA.

**ENOMEM**
:	Insufficient memory to complete the operation.


# NOTES

Client code should open all the devices it intends to use with
**ibv_open_device()** before calling **ibv_free_device_list()**. Once it frees
the array with **ibv_free_device_list()**, it will be able to use only the
open devices; pointers to unopened devices will no longer be valid.

Setting the environment variable **IBV_SHOW_WARNINGS** will cause warnings to
be emitted to stderr if a kernel verbs device is discovered, but no
corresponding userspace driver can be found for it.

# SEE ALSO

**ibv_fork_init**(3),
**ibv_get_device_guid**(3),
**ibv_get_device_name**(3),
**ibv_open_device**(3)

# AUTHOR

Dotan Barak <dotanba@gmail.com>
