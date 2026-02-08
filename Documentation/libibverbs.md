# Introduction

libibverbs is a library that allows userspace programs direct
access to high-performance network hardware.  See the Verbs
Semantics section at the end of this document for details
on RDMA and verbs constructs.

# Using libibverbs

### Device nodes

The verbs library expects special character device files named
/dev/infiniband/uverbsN to be created.  When you load the kernel
modules, including both the low-level driver for your IB hardware as
well as the ib_uverbs module, you should see one or more uverbsN
entries in /sys/class/infiniband_verbs in addition to the
/dev/infiniband/uverbsN character device files.

To create the appropriate character device files automatically with
udev, a rule like

    KERNEL="uverbs*", NAME="infiniband/%k"

can be used.  This will create device nodes named

    /dev/infiniband/uverbs0

and so on.  Since the RDMA userspace verbs should be safe for use by
non-privileged users, you may want to add an appropriate MODE or GROUP
to your udev rule.

### Permissions

To use IB verbs from userspace, a process must be able to access the
appropriate /dev/infiniband/uverbsN special device file.  You can
check the permissions on this file with the command

	ls -l /dev/infiniband/uverbs*

Make sure that the permissions on these files are such that the
user/group that your verbs program runs as can access the device file.

To use IB verbs from userspace, a process must also have permission to
tell the kernel to lock sufficient memory for all of your registered
memory regions as well as the memory used internally by IB resources
such as queue pairs (QPs) and completion queues (CQs).  To check your
resource limits, use the command

	ulimit -l

(or "limit memorylocked" for csh-like shells).

If you see a small number such as 32 (the units are KB) then you will
need to increase this limit.  This is usually done for ordinary users
via the file /etc/security/limits.conf.  More configuration may be
necessary if you are logging in via OpenSSH and your sshd is
configured to use privilege separation.

# Debugging

### Enabling debug prints

Library and providers debug prints can be enabled using the `VERBS_LOG_LEVEL`
environment variable, the output shall be written to the file provided in the
`VERBS_LOG_FILE` environment variable. When the library is compiled in debug
mode and no file is provided the output will be written to stderr.

Note: some of the debug prints are only available when the library is compiled
in debug mode.

The following table describes the expected behavior when VERBS_LOG_LEVEL is set:
|                 | Release                         | Debug                                          |
|-----------------|---------------------------------|------------------------------------------------|
| Regular prints  | Output to VERBS_LOG_FILE if set | Output to VERBS_LOG_FILE, or stderr if not set |
| Datapath prints | Compiled out, no output         | Output to VERBS_LOG_FILE, or stderr if not set |


# Verbs Semantics

Verbs is defined by the InfiniBand Architecture Specification
(vol. 1, chapter 11) as an abstract definition of the functionality
provided by an Infiniband NIC.  libibverbs was designed as a formal
software API aligned with that abstraction.  As a result, API names,
including the library name, are closely aligned with those defined
for Infiniband.

However, the library and API have evolved to support additional
high-performance transports and NICs.  libibverbs constructs have
expanded beyond their traditional roles and definitions, except that
the original Infiniband naming has been kept for backwards
compatibility purposes.

Today, verbs can be viewed as defining software primitives for
network hardware supporting one or more of the following:

- Network queues are directly accessible from user space.
- Network hardware can directly access application memory buffers.
- The transport supports RDMA operations.

The following sections describe select libibverbs constructs in terms
of their current semantics and, where appropriate, historical context.
Items are ordered conceptually.

*RDMA*
: RDMA takes on several different meanings based on context,
  which are further described below.  RDMA stands for remote direct memory
  access.  Historically, RDMA referred to network operations which could
  directly read or write application data buffers at the target.
  The use of the term RDMA has since evolved to encompass not just
  network operations, but also the key features of such devices:

  - Zero-copy: no intermediate buffering
  - Low CPU utilization: transport offload
  - High bandwidth and low latency

*RDMA Verbs*
: RDMA verbs is the more generic name given to the libibverbs API,
  as it implies support for other transports beyond Infiniband.
  A device which supports RDMA verbs is accessible through this library.

  A common, but restricted, industry use of the term RDMA verbs frequently
  implies the subset of libibverbs APIs and semantics focused on reliable-
  connected communication.  This document will use the term RDMA verbs as
  a synonym for the libibverbs API as a whole.

*RDMA-Core*
: The rdma-core is a set of libraries for interfacing with the Linux
  kernel RDMA subsystem.  Two key rdma-core libraries are this one,
  libibverbs, and the librdmacm, which is used to establish connections.

  The rdma-core is considered an essential component of Linux RDMA.
  It is used to ensure that the kernel ABI is stable and implements the
  user space portion of the kernel RDMA IOCTL API.

*RDMA Device / Verbs Device / NIC*
: An RDMA or verbs device is one which is accessible through the Linux
  RDMA subsystem, and as a result, plugs into the libibverbs and rdma-core
  framework.  NICs plug into the RDMA subsystem to expose hardware
  primitives supported by verbs (described above) or RDMA-like features.

  NICs do not necessarily need to support RDMA operations or transports
  in order to leverage the rdma-core infrastructure.  It is sufficient for
  a NIC to expose similar features found in RDMA devices.

*RDMA Operation*
: RDMA operations refer to network transport functions that read or write
  data buffers at the target without host CPU intervention.  RDMA reads
  copy data from a remote memory region to the network and return the data
  to the initiator of the request.  RDMA writes copy data from a local
  memory region to the network and place it directly into a memory region
  at the target.

*RDMA Transport*
: An RDMA transport can be considered any transport that supports RDMA
  operations.  Common RDMA transports include Infiniband,
  RoCE (RDMA over Converged Ethernet), RoCE version 2, and iWarp.  RoCE
  and RoCEv2 are Infiniband transports over the Ethernet link layer, with
  differences only in their lower-level addressing.
  However, the term Infiniband usually refers to the Infiniband transport
  over the Infiniband link layer.  RoCE is used when explicitly
  referring to Ethernet based solutions.  RoCE version 2 is often included
  or implied by references to RoCE.

*Device Node*
: The original intent of device node type was to identify if an Infiniband
  device was a NIC, switch, or router.  Infiniband NICs were labeled as
  channel adapters (CA).  Node type was extended to identify the transport
  being manipulated by verb primitives.  Devices which implemented other
  transports were assigned new node types.  As a result, applications which
  targeted a specific transport, such as Infiniband or RoCE, relied on node
  type to indirectly identify the transport.

*Protection Domain (PD)*
: A protection domain provides process-level isolation of resources and is
  considered a fundamental security construct for Linux RDMA devices.
  A PD defines a boundary between memory regions and queue pairs.  A
  network data transfer is associated with a single queue pair.  That queue
  pair may only access a memory region that shares the same protection
  domain as itself.  This prevents a user space process from accessing
  memory buffers outside of its address space.

  Protection domains provide security for regions accessed
  by both local and remote operations.  Local access includes work requests
  posted to HW command queues which reference memory regions.  Remote
  access includes RDMA operations which read or write memory regions.

  A queue pair is associated with a single PD.  The PD verifies that hardware
  access to a given lkey or rkey is valid for the specified QP and the
  initiating or targeted process has permission to the lkey or rkey. Vendors
  may implement a PD using a variety of mechanisms, but are required to meet
  the defined security isolation.

*Memory Region (MR)*
: A memory region identifies a virtual address range known to the NIC.
  MRs are registered address ranges accessible by the NIC for local and
  remote operations.  The process of creating a MR associates the given
  virtual address range with a protection domain, in order to ensure
  process-level isolation.

  Once allocated, data transfers reference the MR using a key value (lkey
  and/or rkey).  When accessing a MR as part of a data transfer, an offset
  into the memory region is specified.  The offset is relative to the start
  of the region and may either be 0-based or based on the region’s starting
  virtual address.

*lkey*
: The lkey is designed as a hardware identifier for a locally accessed data
  buffer.  Because work requests are formatted by user space software and
  may be written directly to hardware queues, hardware must validate
  that the memory buffers being referenced are accessible to the application.

  NIC hardware may not have access to the operating system's
  virtual address translation table.  Instead, hardware can use the lkey to
  identify the registered memory region, which in turn identifies a protection
  domain, which finally identifies the calling process.  The protection domain
  the processing queue pair must match that of the accessed memory region.
  This prevents an application from sending data from buffers outside of its
  virtual address space.

*rkey*
: The rkey is designed as a transport identifier for remotely accessed data
  buffers.  It's conceptually like an lkey, but the value is
  shared across the network.  An rkey is associated with transport
  permissions.

*Completion Queue (CQ)*
: A completion queue is designed to represent a hardware queue where the
  status of asynchronous operations is reported.  Each asynchronous
  operation (i.e. data transfer) is expected to write a single entry
  into the completion queue.

*Queue Pair (QP)*
: A queue pair was originally defined as a transport addressable set of
  hardware queues, with a QP consisting of send and receive queues (defined
  below).  The evolved definition of a QP refers only to the transport
  addressability of an endpoint.  A QP's address is identified as a
  queue pair number (QPN), which is conceptually like a transport
  port number.  In networking stack models, a QP is considered a transport
  layer object.

  The internal structure of the QP is not constrained to a pair of queues.
  The number of hardware queues and their purpose may vary based on how
  the QP is configured.  A QP may have 0 or more command queues used for
  posting data transfer requests (send queues) and 0 or more command queues
  for posting data buffers used to receive incoming messages (receive queues).

*Receive Queue (RQ)*
: Receive queues are command queues belonging to queue pairs.  Receive
  commands post application buffers to receive incoming data.

  Receive queues are configured as part of queue pair setup.  A RQ is
  accessed indirectly through the QP when submitting receive work requests.

*Shared Receive Queue (SRQ)*
: A shared receive queue is a single hardware command queue for posting
  buffers to receive incoming data.  This command queue may be shared
  among multiple QPs, such that data that arrives on any associated QP
  may retrieve a previously posted buffer from the SRQ.  QPs that share
  the same SRQ coordinate their access to posted buffers such that a
  single posted operation is matched with a single incoming message.

  Unlike receive queues, SRQs are accessed directly by applications to
  submit receive work requests.

*Send Queue (SQ)*
: More generically, a send queue is a transmit queue.  It
  represents a command queue for operations that initiate a network operation.
  A send queue may also be used to submit commands that update hardware
  resources, such as updating memory regions.  Network operations submitted
  through the send queue include message sends, RDMA reads, RDMA writes, and
  atomic operations, among others.

  Send queues are configured as part of queue pair setup.  A SQ is
  accessed indirectly through the QP when submitting send work requests.

*Send Message*
: A send message refers to a specific type of transport data transfer.
  A send message operation copies data from a local buffer to the network
  and transfers the data as a single transport unit.  The receiving NIC
  copies the data from the network into a user posted receive message
  buffer(s).

  Like the term RDMA, the meaning of send is context dependent.  Send could
  refer to the transmit command queue, any operation posted to the transmit
  (send) queue, or a send message operation.

*Work Request (WR)*
: A work request is a command submitted to a queue pair, work queue, or
  shared receive queue.  Work requests define the type of network operation
  to perform, including references to any memory regions the operation will
  access.

  A send work request is a transmit operation that is directed to the send
  queue of a queue pair.  A receive work request is an operation posted
  to either a shared receive queue or a QP's receive queue.

*Address Handle (AH)*
: An address handle identifies the link and/or network layer addressing to
  a network port or multicast group.

  With legacy Infiniband, an address handle is a link layer object.  For other
  transports, including RoCE, the address handle is a network layer object.

*Global Identifier (GID)*
: Infiniband defines a GID as an optional network-layer or multicast address.
  Because GIDs are large enough to store an IPv6 address, their use has evolved
  to support other transports.  A GID identifies a network port, with the most
  well-known GIDs being IPv4 and IPv6 addresses.

*GID Type*
: The GID type determines the specific type of GID address being referenced.
  Additionally, it identifies the set of addressing headers underneath the
  transport header.

  An RDMA transport protocol may be layered over different networking stacks.
  An RDMA transport may layer directly over a link layer (like Infiniband or
  Ethernet), over the network layer (such as IP), or another transport
  layer (such as TCP or UDP).  The GID type conveys how the RDMA transport
  stack is constructed, as well as how the GID address is interpreted.

*GID Index*
: RDMA addresses are securely managed to ensure that unprivileged
  applications do not inject arbitrary source addresses into the network.
  Transport addresses are injected by the queue pair.  Network addresses
  are selected from a set of addresses stored in a source addressing table.

  The source addressing table is referred to as a GID table.  The GID index
  identifies an entry into that table.  The GID table exposed to a user
  space process contains only those addresses usable by that process.
  Queue pairs are frequently assigned a specific GID index to use for their
  source network address when initially configured.

*Device Context*
: Identifies an instance of an opened RDMA device.

*command fd - cmd_fd*
: File descriptor used to communicate with the kernel device driver.
  Associated with the device context and opened by the library.
  The cmd_fd communicates with the kernel via ioctl’s and is used
  to allocate, configure, and release device resources.

  Applications interact with the cmd_fd indirectly by calling libibverbs
  function calls.

*async_fd*
: File descriptor used to report asynchronous events.
  Associated with the device context and opened by the library.

  Applications may interact directly with the async_fd, such as waiting
  on the fd via select/poll, to receive notifications when an async event
  has been reported.

*Job ID*
: A job ID identifies a single distributed application.  The job object
  is a device-level object that maps to a job ID and may be shared between
  processes.  The configuration of a job object, such as assigning its
  job ID value, is considered a privileged operation.

  Multiple job objects, each assigned the same job ID value, may be needed
  to represent a single, higher-level logical job running on the network.
  This may be nessary for jobs that span multiple RDMA devices, for
  example, where each job object may be configured for different source
  addressing.

*Job Key*
: A job key associates a job object with a specific protection domain.  This
  provides secure access to the actual job ID value stored with the job
  object, while restricting which memory regions data transfers to / from
  that job may access.

*Address Table*
: An address table is a virtual address array associated with a job object.
  The address table allows local processes that belong to the same job to
  share addressing and scalable encryption information to peer QPs.

  The address table is an optional but integrated component to a job
  object.
