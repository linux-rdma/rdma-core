---
date: 2020-04-24
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_QUERY_GID_EX
---

# NAME

ibv_query_gid_ex - Query an InfiniBand port's GID table entry

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_query_gid_ex(struct ibv_context *context,
                     uint32_t port_num,
                     uint32_t gid_index,
                     struct ibv_gid_entry *entry,
                     uint32_t flags);
```

# DESCRIPTION

**ibv_query_gid_ex()** returns the GID entry at *entry* for
*gid_index* of port *port_num* for device context *context*.

# ARGUMENTS

*context*
:	The context of the device to query.

*port_num*
:	The number of port to query its GID table.

*gid_index*
:	The index of the GID table entry to query.

## *entry* Argument
:	An ibv_gid_entry struct, as defined in <infiniband/verbs.h>.
```c
struct ibv_gid_entry {
		union ibv_gid gid;
		uint32_t gid_index;
		uint32_t port_num;
		uint32_t gid_type;
		uint32_t ndev_ifindex;
};
```

	*gid*
:			The GID entry.

	*gid_index*
:			The GID table index of this entry.

	*port_num*
:			The port number that this GID belongs to.

	*gid_type*
:			enum ibv_gid_type, can be one of IBV_GID_TYPE_IB, IBV_GID_TYPE_ROCE_V1 or IBV_GID_TYPE_ROCE_V2.

	*ndev_ifindex*
:			The interface index of the net device associated with this GID.
			It is 0 if there is no net device associated with it.

*flags*
:	Extra fields to query post *ndev_ifindex*, for now must be 0.

# RETURN VALUE

**ibv_query_gid_ex()** returns 0 on success or errno value on error.

# ERRORS

ENODATA
:	*gid_index* is within the GID table size of port *port_num* but there is no data in this index.

# SEE ALSO

**ibv_open_device**(3),
**ibv_query_device**(3),
**ibv_query_pkey**(3),
**ibv_query_port**(3),
**ibv_query_gid_table**(3)

# AUTHOR

Parav Pandit <parav@nvidia.com>
