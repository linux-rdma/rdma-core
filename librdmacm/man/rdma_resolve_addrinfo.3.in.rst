=====================
RDMA_RESOLVE_ADDRINFO
=====================

---------------------------------------------------------
Resolve RDMA addresses which supports both DNS and IB SA.
---------------------------------------------------------

:Date: 2025-02-06
:Manual section: 3
:Manual group: Librdmacm Programmer's Manual


SYNOPSIS
========

#include <rdma/rdma_cma.h>

int rdma_resolve_addrinfo(struct rdma_cm_id \*id, const char \*node, const char \*service, const struct rdma_addrinfo \*hints);

ARGUMENTS
=========

id	RDMA identifier.

node    Optional, name, dotted-decimal IPv4, or IPv6 hex address to resolve.

service The service name or port number of address.

hints   Reference to an rdma_addrinfo structure containing hints about the type of service the caller supports.

DESCRIPTION
===========

This call submits an asynchronous address resolution request. The behavior is similar to rdma_getaddrinfo(),
except that the operation is asynchronous, generating an event on the RDMA CM event channel that is
associated with the specified rdma_cm_id when complete. The %node, %service, and %hints parameters are defined
similarly to rdma_getaddrinfo().

RETURN VALUE
============

Returns 0 on success. Success indicates that asynchronous address resolution was initiated. The result of
the resolution, whether successful or failed, will be reported as an event on the related event channel.

Returns -1 on error, errno will be set to indicate the failure reason. The address resolution was not
started, and no event will be generated on the event channel.

NOTES
=====

This call supports both DNS and IB SA resolution, depends on the hints.ai_flags:
  - RAI_DNS: Performs address resolution using DNS.
  - RAI_SA: Performs address resolution using the Infiniband SA. The rdma_cm_id associated with the call must be bound to an Infiniband port, or an error will occur. The %node parameter must be null (not supported). %Service should be an IB service name or ID.

These 2 flags are mutual-exclusive; If none of them is set then DNS is the default.

The cm event RDMA_CM_EVENT_ADDRINFO_RESOLVED (on success) or RDMA_CM_EVENT_ADDRINFO_ERROR (on failure) is generated.

SEE ALSO
========

rdma_getaddrinfo(3), rdma_query_addrinfo(3)

AUTHOR
======

Mark Zhang <markzhang@nvidia.com>
