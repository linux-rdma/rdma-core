---
date: 2019-01-16
footer: librdmacm
header: "Librdmacm Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: RDMA_ESTABLISH
---

# NAME

rdma_establish - Complete an active connection request.

# SYNOPSIS

```c
#include <rdma/rdma_cma.h>

int rdma_establish(struct rdma_cm_id *id);
```

# DESCRIPTION

**rdma_establish()** Acknowledge an incoming connection response event and complete the connection establishment.

Notes:

If a QP has not been created on the rdma_cm_id, this function should be called by the active side to complete the connection,

after getting connect response event.

This will trigger a connection established event on the passive side.

This function should not be used on an rdma_cm_id on which a QP has been created.

# ARGUMENTS

*id*
:    RDMA identifier.

# RETURN VALUE

**rdma_establish()** returns 0 on success, or -1 on error.  If an error occurs, errno will be set to indicate the failure reason.

# SEE ALSO

**rdma_connect**(3),
**rdma_disconnect**(3)
**rdma_get_cm_event**(3)

# AUTHORS

Danit Goldberg <danitg@mellanox.com>

Yossi Itigin <yosefe@mellanox.com>



