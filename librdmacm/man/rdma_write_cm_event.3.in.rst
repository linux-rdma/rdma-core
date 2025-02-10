===================
RDMA_WRITE_CM_EVENT
===================

-------------------------
Write an event into a CM.
-------------------------

:Date: 2025-02-06
:Manual section: 3
:Manual group: Librdmacm Programmer's Manual


SYNOPSIS
========

#include <rdma/rdma_cma.h>

int rdma_write_cm_event(struct rdma_cm_id \*id, enum rdma_cm_event_type event, int status, uint64_t arg);

ARGUMENTS
=========

id      The RDMA identifier associated with the reported rdma_cm_event.

event   The communication event value to report. This should be set to RDMA_CM_EVENT_USER.

status  The status value reported in the rdma_cm_event.

arg     A user-specified value reported in the rdma_cm_event.

DESCRIPTION
===========

Write an event into a CM, with a status and an argument.

RETURN VALUE
============

On success 0 is returned, on error -1 is returned, errno will be set to indicate the failure reason.

NOTES
=====

This call allows an application to write a user-defined event to the event channel associated with the
specified rdma_cm_id. Valid user events are: RDMA_CM_EVENT_USER. Applications may use this for internal
signaling purposes, such as waking a thread blocked on the event channel.

SEE ALSO
========

rdma_get_cm_event(3)

AUTHOR
======

Mark Zhang <markzhang@nvidia.com>
