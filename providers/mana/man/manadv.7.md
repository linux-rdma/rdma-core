---
layout: page
title: MANADV
section: 7
tagline: Verbs
date: 2022-05-16
header: "MANA Direct Verbs Manual"
footer: mana
---

# NAME
manadv - Direct verbs for mana devices

This provides low level access to mana devices to perform direct operations,
without general branching performed by libibverbs.

# DESCRIPTION
The libibverbs API is an abstract one. It is agnostic to any underlying
provider specific implementation. While this abstraction has the advantage
of user applications portability, it has a performance penalty. For some
applications optimizing performance is more important than portability.

The mana direct verbs API is intended for such applications.
It exposes mana specific low level operations, allowing the application
to bypass the libibverbs API.

The mana direct verbs API exposes queues for IBV_QPT_RAW_PACKET QPs.
Applications can use manadv_set_context_attr() to supply external buffer
allocators and manadv_init_obj() to obtain the queue information, then
implement their own queue operations.

Raw packet QPs also support the libibverbs datapath without external buffer
allocators. Send queues accept complete Ethernet frames through ibv_post_send().
Receive work queues are associated with an RSS QP through a receive work queue
indirection table and accept buffers through ibv_post_wq_recv(). Completions
are returned by ibv_poll_cq(). Each raw completion queue belongs to a single
send or receive queue and cannot be shared. Receive work requests can only be
posted while the work queue is associated with an RSS QP.

The send datapath supports IBV_WR_SEND and IBV_SEND_SIGNALED, but not inline
sends or transmit offloads. Receive completions report the packet length and
IBV_WC_IP_CSUM_OK when the hardware verifies the transport checksum without
detecting a checksum error.

At hardware layer, IBV_QPT_RAW_PACKET
QP shares the same hardware resource as the Ethernet port used in the kernel.
The software checks for exclusive use of the hardware Ethernet port, and will
fail the QP creation if the port is already in use. To create a
IBV_QPT_RAW_PACKET on a specified port, the user needs to configure the system
in such a way that this port is not used by any other software (including the
Kernel). If the port is used, ibv_create_qp() will fail with errno set to EBUSY.

The direct include of manadv.h together with linkage to mana library will
allow usage of this new interface.

# SEE ALSO
**verbs**(7)

# AUTHORS
Long Li <longli@microsoft.com>
