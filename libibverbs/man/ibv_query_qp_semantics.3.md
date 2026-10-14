---
date: 2026-08-08
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_query_qp_semantics
---

# NAME

ibv_query_qp_semantics - query the ordering and delivery semantics of a queue pair type

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_query_qp_semantics(struct ibv_context *context,
                           enum ibv_qp_type qp_type,
                           uint32_t port_num, uint8_t sgid_index,
                           struct ibv_qp_semantics *qp_semantics,
                           size_t qp_semantic_len);
```

# DESCRIPTION

**ibv_query_qp_semantics()** returns the message and data ordering
guarantees that *context* provides for queue pairs of type *qp_type* on port
*port_num* using the source GID at *sgid_index*.

Ordering is normally implied by the queue pair type, which forces an
application to consult the transport specification to learn what a device
guarantees, and forces the device to provide guarantees the application may
not need. These verbs make the guarantees explicit in both directions.

The exchange is one-way: **ibv_query_qp_semantics()** reports what the
device is able to guarantee, and the application may then **clear** the
guarantees it does not require and pass the structure to
**ibv_create_qp_ex**(3) through *IBV_QP_INIT_ATTR_QP_SEMANTICS*. Relaxing a
requirement lets the device make optimizations. For example with Ultra
Ethernet, typically by selecting an unordered rather than an ordered
packet delivery mode. An application MUST NOT request a guarantee that
was not advertised; doing so causes queue pair creation to fail.

*qp_semantic_len* is the size of the caller's *struct ibv_qp_semantics*,
allowing the structure to grow compatibly.

# ARGUMENTS

## qp_semantics

```c
struct ibv_qp_semantics {
	uint32_t	comp_mask;
	uint32_t	msg_order;
	uint32_t	max_rdma_raw_size;
	uint32_t	max_rdma_war_size;
	uint32_t	max_rdma_waw_size;
	uint32_t	max_pdu;
	uint8_t		imm_data_size;
	unsigned int	usage_flags;
};
```

*comp_mask*
:	Bitmask from *enum ibv_qp_semantics_mask* reporting which members are
	valid: *IBV_QP_SEMANTICS_MASK_MSG_ORDER*, *_RAW*, *_WAR*, *_WAW*,
	*_PDU*, *_IMM* and *_USAGE* correspond to *msg_order*,
	*max_rdma_raw_size*, *max_rdma_war_size*, *max_rdma_waw_size*,
	*max_pdu*, *imm_data_size* and *usage_flags* respectively. A member
	whose bit is clear MUST be ignored.

*msg_order*
:	Bitmask from *enum ibv_qp_msg_order* of the ordering guarantees
	provided, described under **MESSAGE ORDERING** below.

*max_rdma_raw_size*, *max_rdma_war_size*, *max_rdma_waw_size*
:	The largest transfer, in bytes, for which the corresponding data
	ordering guarantee holds: the target memory reflects the order of a
	read after a write, a write after a read, or a write after a write,
	under both the *IBV_ORDER_RDMA_* bit and the plain bit for that pair.
	**A value of zero means the device does not provide that ordering at
	all**, in which case both of those *msg_order* bits are also clear.
	There is no read-after-read size, since two reads leave memory
	unchanged.

*max_pdu*
:	The largest protocol data unit the queue pair can be configured to
	emit, in bytes. Zero means the device does not allow the value to be
	modified.

*imm_data_size*
:	The widest immediate data the queue pair supports, from
	*enum ibv_imm_data_size*: *IBV_IMM_DATA_SIZE_32* or
	*IBV_IMM_DATA_SIZE_64*. A device reporting *IBV_IMM_DATA_SIZE_64* also
	supports 32-bit immediate data. 64-bit immediate data additionally
	requires *IBV_DEVICE_IMM64*; see **ibv_query_device_ex**(3).

*usage_flags*
:	Bitmask from *enum ibv_qp_use_flags* of optional behaviours the queue
	pair supports:

	*IBV_QP_USAGE_IMM_DATA_RQ*
	:	Immediate data consumes a receive queue entry.

# MESSAGE ORDERING

Each bit of *msg_order* names an ordered pair of operation types. A bit
being set means that, when the two operations address overlapping memory,
the second is not reordered ahead of the first: they are transmitted in the
order submitted, and the target observes them in that order. A bit being
clear means the device may reorder the two freely, and an application that
requires the ordering must enforce it itself, for example by waiting for the
first operation to complete.

The names read as *X* after *Y*, where **R** is a read, **W** a write and
**S** a send.

The first group orders atomic operations against other atomic operations:

*IBV_ORDER_ATOMIC_RAR*
:	An atomic read issued after an earlier atomic read is not reordered
	ahead of it.

*IBV_ORDER_ATOMIC_RAW*
:	An atomic read issued after an earlier atomic write is not reordered
	ahead of it, so the read observes the write.

*IBV_ORDER_ATOMIC_WAR*
:	An atomic write issued after an earlier atomic read is not reordered
	ahead of it, so the read does not observe the write.

*IBV_ORDER_ATOMIC_WAW*
:	An atomic write issued after an earlier atomic write is not reordered
	ahead of it, so the later write lands second.

The second group orders RDMA operations against other RDMA operations:

*IBV_ORDER_RDMA_RAR*
:	An RDMA read issued after an earlier RDMA read is not reordered ahead
	of it.

*IBV_ORDER_RDMA_RAW*
:	An RDMA read issued after an earlier RDMA write is not reordered ahead
	of it, so the read returns the written data. Bounded by
	*max_rdma_raw_size*.

*IBV_ORDER_RDMA_WAR*
:	An RDMA write issued after an earlier RDMA read is not reordered ahead
	of it, so the read returns the data as it was before the write.
	Bounded by *max_rdma_war_size*.

*IBV_ORDER_RDMA_WAW*
:	An RDMA write issued after an earlier RDMA write is not reordered
	ahead of it, so the later write lands second. Bounded by
	*max_rdma_waw_size*.

The third group orders sends against atomic and RDMA operations, and against
other sends:

*IBV_ORDER_RAS*
:	A read issued after an earlier send is not reordered ahead of it.

*IBV_ORDER_SAR*
:	A send issued after an earlier read is not reordered ahead of it.

*IBV_ORDER_SAS*
:	A send issued after an earlier send is not reordered ahead of it, so
	messages arrive in the order submitted.

*IBV_ORDER_SAW*
:	A send issued after an earlier write is not reordered ahead of it.

*IBV_ORDER_WAS*
:	A write issued after an earlier send is not reordered ahead of it.

The fourth group orders atomic and RDMA operations against one another,
irrespective of which of the two an individual operation is:

*IBV_ORDER_RAR*
:	A read issued after an earlier read is not reordered ahead of it.

*IBV_ORDER_RAW*
:	A read issued after an earlier write is not reordered ahead of it.

*IBV_ORDER_WAR*
:	A write issued after an earlier read is not reordered ahead of it.

*IBV_ORDER_WAW*
:	A write issued after an earlier write is not reordered ahead of it.

# RETURN VALUE

**ibv_query_qp_semantics()** returns 0 on success, or the value of *errno*
on failure. EOPNOTSUPP is returned if the provider does not implement the
operation or does not support *qp_type*, and EINVAL if *qp_semantics* is
NULL or *qp_semantic_len* is too small.

# NOTES

Queue pair semantics are supported only by devices reporting
*IBV_DEVICE_RU* in *device_cap_flags_ex*.

An application that does not query the semantics, or that does not set
*IBV_QP_INIT_ATTR_QP_SEMANTICS* at creation, receives the queue pair type's
default guarantees.

# SEE ALSO

**ibv_create_qp_ex**(3),
**ibv_attach_mr**(3),
**ibv_query_device_ex**(3),
**ibv_post_send**(3),
**ibv_wr_post**(3),
**ibv_uet**(7)

# AUTHOR

Eric Davis <eric.davis@broadcom.com>
