---
date: 2025-12-7
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_dm_export_dmabuf_fd
---

# NAME

ibv_dm_export_dmabuf_fd - export dmabuf fd for a given ibv_dm.

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_dm_export_dmabuf_fd(struct ibv_dm *dm);
```

# DESCRIPTION

**ibv_dm_export_dmabuf_fd()** exports a dmabuf fd that is associated with the given
*dm*.

The returned fd can be later used for DMA and RDMA operations associated with it.

Once the usage has been ended close() should be called while supplying the fd.

This call will release resources that were earlier allocated using the **ibv_dm_export_dmabuf_fd()** API.

# ARGUMENTS

*dm*
:	An ibv_dm pointer to export the dmabuf fd for its memory.

# RETURN VALUE

**ibv_dm_export_dmabuf_fd()** returns an fd number >= 0 upon success, or -1 if the request fails and errno set to the error.

# SEE ALSO

**ibv_reg_mr_ex**(3)

# AUTHOR

Yishai Hadas <yishaih@nvidia.com>
