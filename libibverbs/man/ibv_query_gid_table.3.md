---
date: 2020-04-24
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_QUERY_GID_TABLE
---

# NAME

ibv_query_gid_table - query an InfiniBand device's GID table

# SYNOPSIS

```c
#include <infiniband/verbs.h>

ssize_t ibv_query_gid_table(struct ibv_context *context,
                            struct ibv_gid_entry *entries,
                            size_t max_entries,
                            uint32_t flags);
```

# DESCRIPTION

**ibv_query_gid_table()** returns the valid GID table entries of the RDMA
device context *context* at the pointer *entries*.

A caller must allocate *entries* array for the GID table entries it
desires to query. This API returns only valid GID table entries.

A caller must pass non zero number of entries at *max_entries* that corresponds
to the size of *entries* array.

*entries* array must be allocated such that it can contain all the valid
GID table entries of the device. If there are more valid GID entries than
the provided value of *max_entries* and *entries* array, the call will fail.
For example, if an RDMA device *context* has a total of 10 valid
GID entries, *entries* should be allocated for at least 10 entries, and
*max_entries* should be set appropriately.

# ARGUMENTS

*context*
:	The context of the device to query.

*entries*
:	Array of ibv_gid_entry structs where the GID entries are returned.
	Please see **ibv_query_gid_ex**(3) man page for *ibv_gid_entry*.

*max_entries*
:	Maximum number of entries that can be returned.

*flags*
:	Extra fields to query post *entries->ndev_ifindex*, for now must be 0.

# RETURN VALUE

**ibv_query_gid_table()** returns the number of entries that were read on success or negative errno value on error.
Number of entries returned is <= max_entries.

# SEE ALSO

**ibv_open_device**(3),
**ibv_query_device**(3),
**ibv_query_port**(3),
**ibv_query_gid_ex**(3)

# AUTHOR

Parav Pandit <parav@nvidia.com>
