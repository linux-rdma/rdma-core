---
date: 2020-5-3
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_import_device
---

# NAME

ibv_import_device - import a device from a given command FD

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_context *ibv_import_device(int cmd_fd);

```


# DESCRIPTION

**ibv_import_device()** returns an *ibv_context* pointer that is associated with the given
*cmd_fd*.

The *cmd_fd* is obtained from the ibv_context cmd_fd member, which must be dup'd (eg by dup(), SCM_RIGHTS, etc)
before being passed to ibv_import_device().

Once the *ibv_context* usage has been ended *ibv_close_device()* should be called.
This call may cleanup whatever is needed/opposite of the import including closing the command FD.

# RETURN VALUE

**ibv_import_device()** returns a pointer to the allocated RDMA context, or NULL if the request fails.

# SEE ALSO

**ibv_open_device**(3),
**ibv_close_device**(3),

# AUTHOR

Yishai Hadas <yishaih@mellanox.com>

