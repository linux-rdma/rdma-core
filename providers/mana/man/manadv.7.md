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

This version of the driver supports one QP type: IBV_QPT_RAW_PACKET. To use
this QP type, the application is required to use manadv_set_context_attr()
to set external buffer allocators for allocating queues, and use
manadv_init_obj() to obtain all the queue information. The application
implements its own queue operations, bypassing libibverbs API for
sending/receiving traffic over the queues. At hardware layer, IBV_QPT_RAW_PACKET
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
