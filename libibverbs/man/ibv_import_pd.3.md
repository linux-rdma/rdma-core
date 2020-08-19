---
date: 2020-5-3
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_import_pd, ibv_unimport_pd
---

# NAME

ibv_import_pd - import a PD from a given ibv_context

ibv_unimport_pd - unimport a PD

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_pd *ibv_import_pd(struct ibv_context *context, uint32_t pd_handle);
void ibv_unimport_pd(struct ibv_pd *pd)

```


# DESCRIPTION

**ibv_import_pd()** returns a protection domain (PD) that is associated with the given
*pd_handle* in the given *context*.

The input *pd_handle* value must be a valid kernel handle for a PD object in the given *context*.
It can be achieved from the original PD by getting its ibv_pd->handle member value.

The returned *ibv_pd* can be used in all verbs that get a protection domain.

**ibv_unimport_pd()** unimport the PD.
Once the PD usage has been ended ibv_dealloc_pd() or ibv_unimport_pd() should be called.
The first one will go to the kernel to destroy the object once the second one way cleanup what
ever is needed/opposite of the import without calling the kernel.

This is the responsibility of the application to coordinate between all ibv_context(s) that use this PD.
Once destroy is done no other process can touch the object except for unimport. All users of the context must
collaborate to ensure this.

# RETURN VALUE

**ibv_import_pd()** returns a pointer to the allocated PD, or NULL if the request fails.

# SEE ALSO

**ibv_alloc_pd**(3),
**ibv_dealloc_pd**(3),

# AUTHOR

Yishai Hadas <yishaih@mellanox.com>

