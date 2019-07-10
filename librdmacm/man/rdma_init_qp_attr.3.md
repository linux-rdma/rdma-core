---
date: 2018-12-31
footer: librdmacm
header: "Librdmacm Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: RDMA_INIT_QP_ATTR
---

# NAME

rdma_init_qp_attr - Returns qp attributes of a rdma_cm_id.

# SYNOPSIS

```c
#include <rdma/rdma_cma.h>

int rdma_init_qp_attr(struct rdma_cm_id *id,
		       struct ibv_qp_attr *qp_attr,
		       int *qp_attr_mask);
```
# DESCRIPTION

**rdma_init_qp_attr()** returns qp attributes of a rdma_cm_id.

Information about qp attributes and qp attributes mask is returned through the *qp_attr* and *qp_attr_mask* parameters.

For details on the qp_attr structure, see ibv_modify_qp.

# ARGUMENTS

*id*
:    RDMA identifier.

*qp_attr*
:    A reference to a qp attributes struct containing response information.

*qp_attr_mask*
:    A reference to a qp attributes mask containing response information.

# RETURN VALUE

**rdma_init_qp_attr()** returns 0 on success, or -1 on error.  If an error occurs, errno will be set to indicate the failure reason.

# SEE ALSO

**rdma_cm**(7),
**ibv_modify_qp**(3)

# AUTHOR

Danit Goldberg <danitg@mellanox.com>
