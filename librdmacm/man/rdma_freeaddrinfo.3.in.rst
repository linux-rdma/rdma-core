=================
RDMA_FREEADDRINFO
=================

-----------------------------------------------------------------------
Frees the list of rdma_addrinfo structures returned by rdma_getaddrinfo
-----------------------------------------------------------------------

:Date: 2025-02-03
:Manual section: 3
:Manual group: Librdmacm Programmer's Manual


SYNOPSIS
========

#include <rdma/rdma_cma.h>

void rdma_freeaddrinfo (struct rdma_addrinfo \*res);

ARGUMENTS
=========

res	List of rdma_addrinfo structures returned by rdma_getaddrinfo.

DESCRIPTION
===========

Frees the list of rdma_addrinfo structures returned by rdma_getaddrinfo.

RETURN VALUE
============

None

SEE ALSO
========

rdma_getaddrinfo(3)

AUTHOR
======

Mark Zhang <markzhang@nvidia.com>
