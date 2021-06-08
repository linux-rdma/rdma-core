---
date: 2021-1-17
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_import_dm ibv_unimport_dm
---

# NAME

ibv_import_dm - import an DM from a given ibv_context

ibv_unimport_dm - unimport an DM

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_dm *ibv_import_dm(struct ibv_context *context, uint32_t dm_handle);
void ibv_unimport_dm(struct ibv_dm *dm)

```


# DESCRIPTION

**ibv_import_dm()** returns a Device memory (DM) that is associated with the given
*dm_handle* in the RDMA context.

The input *dm_handle* value must be a valid kernel handle for an DM object in the assosicated RDMA context.
It can be achieved from the original DM by getting its ibv_dm->handle member value.

**ibv_unimport_dm()** un import the DM.
Once the DM usage has been ended ibv_free_dm() or ibv_unimport_dm() should be called.
The first one will go to the kernel to destroy the object once the second one way cleanup what
ever is needed/opposite of the import without calling the kernel.

This is the responsibility of the application to coordinate between all ibv_context(s) that use this DM.
Once destroy is done no other process can touch the object except for unimport. All users of the context must
collaborate to ensure this.

# RETURN VALUE

**ibv_import_dm()** returns a pointer to the allocated DM, or NULL if the request fails and errno is set.

# NOTES

# SEE ALSO

**ibv_alloc_dm**(3),
**ibv_free_dm**(3),

# AUTHOR

Maor Gottlieb <maorg@nvidia.com>

