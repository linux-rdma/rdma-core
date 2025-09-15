===================
RDMA_QUERY_ADDRINFO
===================

---------------------------------------
Query the resolved address information.
---------------------------------------

:Date: 2025-02-06
:Manual section: 3
:Manual group: Librdmacm Programmer's Manual


SYNOPSIS
========

#include <rdma/rdma_cma.h>

int rdma_query_addrinfo(struct rdma_cm_id \*id, struct rdma_addrinfo \*\*info);

ARGUMENTS
=========

id      RDMA identifier.

info    A pointer to a linked list of rdma_addrinfo structures containing resolved information.

DESCRIPTION
===========

This function retrieves the resulting rdma_addrinfo structures from a successful rdma_resolve_addrinfo() operation.

RETURN VALUE
============

On success 0 is returned, info contains a resolved address information
On error -1 is returned, errno will be set to indicate the failure reason.

NOTES
=====

The info must be released with rdma_freeaddrinfo(3)


SEE ALSO
========

rdma_getaddrinfo(3), rdma_freeaddrinfo(3), rdma_resolve_addrinfo(3)

AUTHOR
======

Mark Zhang <markzhang@nvidia.com>
