---
date: 2020-02-02
footer: librdmacm
header: "Librdmacm Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: RDMA_GET_REMOTE_ECE
---

# NAME

rdma_get_remote_ece - Get remote ECE paraemters as received from the peer.

# SYNOPSIS

```c
#include <rdma/rdma_cma.h>

int rdma_get_remote_ece(struct rdma_cm_id *id, struct ibv_ece *ece);
```
# DESCRIPTION

**rdma_get_remote_ece()** get ECE parameters as were received from the communication peer.

This function is suppose to be used by the users of external QPs. The call needs
to be performed before replying to the peer and needed to allow for the passive
side to know ECE options of other side.

Being used by external QP and RDMA_CM doesn't manage that QP, the peer needs
to call to libibverbs API by itself.

Usual flow for the passive side will be:

 * ibv_create_qp() <- create data QP.
 * ece = rdma_get_remote_ece() <- get ECE options from remote peer
 * ibv_set_ece(ece) <- set local ECE options with data received from the peer.
 * ibv_modify_qp() <- enable data QP.
 * rdma_set_local_ece(ece) <- set desired ECE options after respective
				libibverbs provider masked unsupported options.
 * rdma_accept()/rdma_establish()/rdma_reject_ece()

# ARGUMENTS

*id
:    RDMA communication identifier.

*ece
:    ECE struct to be filled.

# RETURN VALUE

**rdma_get_remote_ece()** returns 0 on success, or -1 on error.  If an error occurs, errno will be set to indicate the failure reason.

# SEE ALSO

**rdma_cm**(7), rdma_set_local_ece(3)

# AUTHOR

Leon Romanovsky <leonro@mellanox.com>
