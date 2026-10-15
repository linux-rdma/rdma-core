---
date: 2026-08-08
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 7
title: ibv_uet
---

# NAME

ibv_uet - overview of the Ultra Ethernet verbs

# DESCRIPTION

Ultra Ethernet (UET) is a transport whose communication model differs from
that of InfiniBand and RoCE in various ways, each of which is reflected in a
set of verbs described here.

Communication is scoped to a **job** rather than to a pair of connected
queue pairs. A **Reliable Unconnected (RU)** queue pair talks to many peers,
so the destination is named on each work request instead of once at connect
time. The guarantees an RU queue pair provides are **queried and negotiated**
rather than implied by its type.

A device implements these verbs if **ibv_query_device_ex**() reports
*IBV_DEVICE_RU* in *device_cap_flags_ex*. Related capabilities
*IBV_DEVICE_IMM64*, *IBV_DEVICE_KEY64* and *IBV_DEVICE_USER_RKEY* are
reported independently and MUST be checked before the corresponding feature
is used.

These flags describe the **device**, which is coarser than the feature they
describe. A device may serve more than one transport. A single port may
carry both a RoCE GID and a UET GID. These are then properties of the
UET paths only. Read them as "some path on this device offers this". Which
transport a given queue pair uses follows from the type of the GID entry it
was given, reported by **ibv_query_gid_ex**().

## Jobs

A job identifies a distributed application. All endpoints that may
communicate with one another belong to the same job, and a transfer between
endpoints of different jobs is rejected by the receiver.

A job is a device-level object that may be shared between processes, and
configuring one is a privileged operation. A single logical application job
spanning several devices needs one job object per device.

Jobs are managed with **ibv_alloc_job**(), **ibv_dealloc_job**() and
**ibv_query_job**(), and may be shared between processes with
**ibv_export_job**() and **ibv_import_job**().

## Job keys

A job key binds a job to a protection domain. It is used to prove
membership to the job, and it restricts which memory regions a transfer
may reach.

Separating the key from the job lets the JobID itself remain privileged: an
unprivileged process is given a job key rather than the JobID value. Job
keys are managed with **ibv_create_jkey**() and **ibv_destroy_jkey**(), and
a key is named on a work request with **ibv_wr_set_job_key**().

## Job address table

An address table is a virtual array of extended addresses belonging to a
job. It lets processes that share a job also share the addressing
information of their peers, so a work request can name a peer by table index
instead of carrying a full address handle.

The table is managed with **ibv_insert_addr**(), **ibv_remove_addr**() and
**ibv_query_addr**(), and an index is selected on a work request by passing
it to **ibv_wr_set_ru_addr**().

## Extended address handles

A UET peer is identified by both network information -- port, destination
address, traffic class -- and transport information, principally the remote
queue pair number. An extended address handle carries both.

*struct ibv_ah_attr_ex* extends *struct ibv_ah_attr* with *remote_qpn*, and
*struct ibv_ah_ex* extends *struct ibv_ah* the same way. They are created
with **ibv_create_ah_ex**(); **ibv_ah_to_ah_ex**() recovers the extended
handle from its base.

## RU queue pairs

*IBV_QPT_RU* is the queue pair type used for Ultra Ethernet. It is
reliable, but does not order messages with respect to one another,
and it is not connected. One RU queue pair reaches every peer in its job.

Because it is unconnected, each work request names its destination. Using
the work request builders **ibv_wr_set_ru_addr**() for the peer and
**ibv_wr_set_job_key**() for the job key, or using **ibv_post_send**() and
the *ru* or *ru_rdma* members of *struct ibv_send_wr*.

## Queue pair numbers

An RU queue pair number is structured rather than opaque. It encodes the
process on the fabric endpoint (PIDonFEP) and a Resource Index service
within that process:

```
 31       30    24 23           12 11             0
+---+-----------+---------------+---------------+
| A |  reserved | Resource Index|   PIDonFEP    |
+---+-----------+---------------+---------------+
```

The following macros describe the layout:

*IBV_QPN_UET_PID_ON_FEP_MASK*, *IBV_QPN_UET_PID_ON_FEP_SHIFT*
:	Mask and shift of the PIDonFEP field, bits 11:0.

*IBV_QPN_UET_RI_MASK*, *IBV_QPN_UET_RI_SHIFT*
:	Mask and shift of the resource index field, bits 23:12.

*IBV_QPN_UET_RESERVED_MASK*
:	Bits 30:24, reserved and MUST be zero. A *source_qpn* with any of them
	set is rejected.

*IBV_QPN_UET_ABSOLUTE_ADDR_BIT*
:	Bit 31. When set on the *source_qpn* passed to **ibv_create_qp_ex**(),
	the queue pair receives using absolute addressing; when clear it
	receives using relative addressing with the QP scoped to a job.

A queue pair number is composed by shifting each field into place, for
example:

```c
qpn = (((pid_on_fep << IBV_QPN_UET_PID_ON_FEP_SHIFT) & IBV_QPN_UET_PID_ON_FEP_MASK) |
       ((ri         << IBV_QPN_UET_RI_SHIFT)         & IBV_QPN_UET_RI_MASK));
```

An application either supplies a queue pair number of its own by setting
*IBV_QP_CREATE_SOURCE_QPN* and *source_qpn*, or lets the provider assign one
by leaving *IBV_QP_CREATE_SOURCE_QPN* clear. A provider-assigned queue pair
number always uses relative addressing.

With relative addressing the receiver interprets an incoming request in the
context of the job it arrived on. With absolute addressing the receiver
accepts the request irrespective of the sender's job, which allows endpoints
of different jobs to communicate where policy permits, targeting client/server
workloads.

## Queue pair semantics

Rather than implying ordering and delivery guarantees from the queue pair
type, a UET device advertises them. **ibv_query_qp_semantics**() returns
what a device supports for a given queue pair type; the application may
clear the guarantees it does not need and pass the result to
**ibv_create_qp_ex**(), allowing the device to optimize for the relaxed
requirements. An application cannot request a guarantee the device did not
advertise.

## Memory regions

Memory regions with UET add three properties beyond a plain registration, all
requested through **ibv_reg_mr_ex**():

A region may be **restricted to a job**, so that only transfers bearing a
matching job key may reach it. A region may be given an
**application-assigned RKey** rather than one chosen by the device, so that
peers can predict it. And a region may be **derived** from an existing one,
exposing a narrower window of the same memory with different access rights
while allowing the device to share page mappings between them.

Regions may additionally be bound to and released from a queue pair with
**ibv_attach_mr**() and **ibv_detach_mr**().

## Keys, immediate data and completions

When a device reports *IBV_DEVICE_KEY64*, memory regions may be named by a
64 bit key, carried in the *lkey64* and *rkey64* members of *struct ibv_mr*.

A wide key is not a widened *lkey*/*rkey*. It is a second name for the same
region, and both are carried, because a region may be reached over more than
one transport. A region registered on a device that also serves RoCE has a
32 bit key for that use and a 64 bit key for UET use. The work request
decides which is meant, *ibv_send_wr.wr.rdma.rkey* is 32 bits wide and
*wr.ru_rdma.rkey64* is 64. A region with no wide name reports zero, which is
why zero cannot be requested as an application-assigned key.

*struct ibv_sge* is not widened, because it is passed as an array and
changing its stride would break the ABI. A 64 bit local key is carried in
*struct ibv_sge64* instead. Sends point *ibv_send_wr.sg64_list* at such an
array and set *IBV_SEND_SGE64* in *send_flags*; the work request builder
uses **ibv_wr_set_sge64**() or **ibv_wr_set_sge64_list**(). Receives have no
flags member to carry that selector, so they use *struct ibv_recv_wr64*
posted with **ibv_post_recv64**().

When a device reports *IBV_DEVICE_IMM64*, immediate data may be 64 bits
wide, sent with **ibv_wr_send_imm64**() or the 64-bit RDMA write variants
and read from a completion with **ibv_wc_read_imm64_data**().

Because an RU queue pair is unconnected, a completion identifies its sender
by job and source rather than by a connected peer. These are read with
**ibv_wc_read_job_id**() and **ibv_wc_read_src_id**(), requested at queue
pair creation with *IBV_WC_EX_WITH_JOB_ID* and *IBV_WC_EX_WITH_SRC_ID*.

# SEE ALSO

**ibv_alloc_job**(3),
**ibv_create_jkey**(3),
**ibv_insert_addr**(3),
**ibv_create_ah_ex**(3),
**ibv_attach_mr**(3),
**ibv_query_qp_semantics**(3),
**ibv_create_qp_ex**(3),
**ibv_reg_mr**(3),
**ibv_wr_post**(3),
**ibv_query_device_ex**(3),
**ibv_create_cq_ex**(3)

# AUTHOR

Eric Davis <eric.davis@broadcom.com>
