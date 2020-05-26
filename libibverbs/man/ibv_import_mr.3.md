---
date: 2020-5-3
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_import_mr ibv_unimport_mr
---

# NAME

ibv_import_mr - import an MR from a given ibv_pd

ibv_unimport_mr - unimport an MR

# SYNOPSIS

```c
#include <infiniband/verbs.h>

struct ibv_mr *ibv_import_mr(struct ibv_pd *pd, uint32_t mr_handle);
void ibv_unimport_mr(struct ibv_mr *mr)

```


# DESCRIPTION

**ibv_import_mr()** returns a Memory region (MR) that is associated with the given
*mr_handle* in the RDMA context that assosicated with the given *pd*.

The input *mr_handle* value must be a valid kernel handle for an MR object in the assosicated RDMA context.
It can be achieved from the original MR by getting its ibv_mr->handle member value.

**ibv_unimport_mr()** un import the MR.
Once the MR usage has been ended ibv_dereg_mr() or ibv_unimport_mr() should be called.
The first one will go to the kernel to destroy the object once the second one way cleanup what
ever is needed/opposite of the import without calling the kernel.

This is the responsibility of the application to coordinate between all ibv_context(s) that use this MR.
Once destroy is done no other process can touch the object except for unimport. All users of the context must
collaborate to ensure this.

# RETURN VALUE

**ibv_import_mr()** returns a pointer to the allocated MR, or NULL if the request fails.

# NOTES

The *addr* field in the imported MR is not applicable, NULL value is expected.

# SEE ALSO

**ibv_reg_mr**(3),
**ibv_reg_dm_mr**(3),
**ibv_reg_mr_iova**(3),
**ibv_reg_mr_iova2**(3),
**ibv_dereg_mr**(3),

# AUTHOR

Yishai Hadas <yishaih@mellanox.com>

