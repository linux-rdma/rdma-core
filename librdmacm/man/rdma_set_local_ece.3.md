---
date: 2020-02-02
footer: librdmacm
header: "Librdmacm Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: RDMA_SET_LOCAL_ECE
---

# NAME

rdma_set_local_ece - Set local ECE paraemters to be used for REQ/REP communication.

# SYNOPSIS

```c
#include <rdma/rdma_cma.h>

int rdma_set_local_ece(struct rdma_cm_id *id, struct ibv_ece *ece);
```
# DESCRIPTION

**rdma_set_local_ece()** set local ECE parameters.

This function is suppose to be used by the users of external QPs. The call needs
to be performed before replying to the peer and needed to configure RDMA_CM with
desired ECE options.

Being used by external QP and RDMA_CM doesn't manage that QP, the peer needs
to call to libibverbs API by itself.

Usual flow for the passive side will be:

 * ibv_create_qp() <- create data QP.
 * ece = ibv_get_ece() <- get ECE from libibvers provider.
 * rdma_set_local_ece(ece) <- set desired ECE options.
 * rdma_connect() <- send connection request
 * ece = rdma_get_remote_ece() <- get ECE options from remote peer
 * ibv_set_ece(ece) <- set local ECE options with data received from the peer.
 * ibv_modify_qp() <- enable data QP.
 * rdma_accept()/rdma_establish()/rdma_reject_ece()

# ARGUMENTS

*id*
:    RDMA communication identifier.

*ece
:    ECE parameters.

# RETURN VALUE

**rdma_set_local_ece()** returns 0 on success, or -1 on error.  If an error occurs, errno will be set to indicate the failure reason.

# SEE ALSO

**rdma_cm**(7), rdma_get_remote_ece(3)

# AUTHOR

Leon Romanovsky <leonro@mellanox.com>
