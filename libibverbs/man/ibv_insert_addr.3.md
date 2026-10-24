---
date: 2026-08-08
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_insert_addr
---

# NAME

ibv_insert_addr - insert an address into a job address table

ibv_remove_addr - remove an address from a job address table

ibv_query_addr - read an address from a job address table

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_insert_addr(struct ibv_job *job, struct ibv_ah_attr_ex *ah_attr,
                    unsigned int addr_idx);

int ibv_remove_addr(struct ibv_job *job, unsigned int addr_idx);

int ibv_query_addr(struct ibv_job *job, unsigned int addr_idx,
                   struct ibv_ah_attr_ex *ah_attr);
```

# DESCRIPTION

A job address table is a virtual array of extended addresses belonging to a
job. Processes that share a job also share the table, so a peer that one
process has resolved can be named by every other process in the job.

Naming a peer by table index avoids passing a full address handle on each
work request, and lets an address be updated in one place. See
**ibv_uet**(7).

**ibv_insert_addr()** stores *ah_attr* at index *addr_idx* of the address
table belonging to *job*, replacing any address already at that index. The
address is resolved as it is for an address handle: on an Ethernet port the
destination MAC is looked up, and the hop limit is taken from the route, so
**ibv_query_addr()** may return a different *hop_limit* than was inserted.
The source GID entry must be of the same address family as the destination.

**ibv_remove_addr()** clears the entry at index *addr_idx*. Work requests
that subsequently reference the index fail.

**ibv_query_addr()** returns in *ah_attr* the address stored at index
*addr_idx*.

An index is selected on a work request with **ibv_wr_set_ru_addr**(),
passing NULL for the address handle, or in the *addr_idx* member of the *ru*
or *ru_rdma* arm of *struct ibv_send_wr*. See **ibv_wr_post**(3) and
**ibv_post_send**(3).

# ARGUMENTS

## job

The job owning the address table, as returned by **ibv_alloc_job**(3) or
**ibv_import_job**(3).

## ah_attr

The extended address identifying the peer: the network address vector in
*ah_attr* and the peer's queue pair number in *remote_qpn*. See
**ibv_create_ah_ex**(3).

## addr_idx

Index into the address table. MUST be less than the *max_addr_entries* the
job was created with; see **ibv_alloc_job**(3).

# RETURN VALUE

All three calls return 0 on success, or the value of *errno* on failure.

# NOTES

The address table is supported only by devices reporting *IBV_DEVICE_RU* in
*device_cap_flags_ex*; on other devices these calls fail with EOPNOTSUPP.
The largest table a device supports is reported as *max_addr_entries* by
**ibv_query_device_ex**(3).

Because the table is shared by every process that has imported the job,
inserting or removing an entry affects them all.

# SEE ALSO

**ibv_alloc_job**(3),
**ibv_create_ah_ex**(3),
**ibv_wr_post**(3),
**ibv_post_send**(3),
**ibv_query_device_ex**(3),
**ibv_uet**(7)

# AUTHOR

Eric Davis <eric.davis@broadcom.com>
