# Hardware tag matching

## Introduction

The MPI standard defines a set of rules, known as tag-matching, for matching
source send operations to destination receives according to the following
attributes:

* Communicator
* User tag - wild card may be specified by the receiver
* Source rank - wild card may be specified by the receiver
* Destination rank - wild card may be specified by the receiver

These matching attributes are specified by all Send and Receive operations.
Send operations from a given source to a given destination are processed in
the order in which the Sends were posted. Receive operations are associated
with the earliest send operation (from any source) that matches the
attributes, in the order in which the Receives were posted. Note that Receive
tags are not necessarily consumed in the order they are created, e.g., a later
generated tag may be consumed if earlier tags do not satisfy the matching
rules.

When a message arrives at the receiver, MPI implementations often classify it
as either 'expected' or 'unexpected' according to whether a Receive operation
with a matching tag has already been posted by the application. In the
expected case, the message may be processed immediately. In the unexpected
case, the message is saved in an unexpected message queue, and will be
processed when a matching Receive operation is posted.

To bound the amount of memory to hold unexpected messages, MPI implementations
use 2 data transfer protocols. The 'eager' protocol is used for small
messages. Eager messages are sent without any prior synchronization and
processed/buffered at the receiver. Typically, with RDMA, a single RDMA-Send
operation is used to transfer the data.

The 'rendezvous' protocol is used for large messages. Initially, only the
message tag is sent along with some meta-data. Only when the tag is matched to
a Receive operation, will the receiver initiate the corresponding data
transfer. A common RDMA implementation is to send the message tag with an
RDMA-Send, and transfer the data with an RDMA-Read issued by the receiver.
When the transfer is complete, the receiver will notify the sender that its
buffer may be freed using an RDMA-Send.

## RDMA tag-matching offload

Tag-matching offload satisfies the following principals:
-   Tag-matching is viewed as an RDMA application, and thus does not affect the
    RDMA transport in any way [(*)](#m1)
-   Tag-matching processing will be split between HW and SW.
    *   HW will hold a bounded prefix of Receive tags
-   HW will process and transfer any expected message that matches a tag held
    in HW.
    *   In case the message uses the rendezvous protocol, HW will also initiate
	the RDMA-Read data transfer and send a notification message when the
	data transfer completes.
-   SW will handle any message that is either unexpected or whose tag is not
    held in HW.

<a name="m1">(*)</a>
This concept can apply to additional application-specific offloads in the
future.

Tag-matching is initially defined for RC transport. Tag-matching messages are
encapsulated in RDMA-Send messages and contain the following headers:

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   Tag Matching Header (TMH):
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Operation  |                  reserved                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      User data (optional)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Tag                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Tag                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Rendezvous Header (RVH):
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Virtual Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Virtual Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Remote Key                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Length                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Tag-matching messages always contain a TMH. An RHV is added for Rendezvous
request messages. The following message formats are defined:
-   Eager request: TMH | payload
-   Rendezvous request: TMH | RHV | optional meta-data [(**)](#m2)
-   Rendezvous response: TMH

Note that rendezvous data transfers are standard RDMA-Reads

<a name="m2">(**)</a>
Rendezvous request messages may also arrive unexpected; in this case, the
message is handled in SW, optionally leveraging additional meta-data passed by
the sender.

As tag-matching messages are standard RDMA-Sends, no special HW support is
needed at the sender. At the receiver, we introduce a new SRQ type - a
Tag-Matching SRQ (TM-SRQ). The TM-SRQ forms the serialization point for
matching messages coming from any of the associated RC connections, and reports
all tag matching completions and events to a dedicated CQ.
2 kinds of buffers may be posted to the TM-SRQ:
-   Buffers associated with tags (tagged-buffers), which are used when a match
    is made by HW
-   Standard SRQ buffers, which are used for unexpected messages (from HW's
    perspective)
When a message is matched by HW, the payload is transferred directly to the
application buffer (both in the eager and the rendezvous case), while skipping
any TM headers. Otherwise, the entire message, including any TM headers, is
scattered to the SRQ buffer.

Since unexpected messages are handled in SW, there exists an inherent race
between the arrival of messages from the wire and posting of new tagged
buffers. For example, consider 2 incoming messages m1 and m2 and matching
buffers b1 and b2 that are posted asynchronously. If b1 is posted after m1
arrives but before m2, m1 would be delivered as an unexpected message while m2
would match b1, violating the ordering rules.

Consequently, whenever HW deems a message unexpected, tag matching must be
disabled for new tags until SW and HW synchronize. This synchronization is
achieved by reporting to HW the number of unexpected messages handled by SW
(with respect to the current posted tags). When the SW and HW are in synch, tag
matching resumes normally.

## Tag Matching Verbs

### Capabilities

Tag matching capabilities are queried by ibv_query_device_ex(), and report the
following attributes:

* **max_rndv_hdr_size** - Max size of rendezvous request header
* **max_num_tags** - Max number of tagged buffers in a TM-SRQ matching list
* **max_ops** - Max number of outstanding tag matching list operations
* **max_sge** - Max number of SGEs in a tagged buffer
* **flags** - the following flags are currently defined:
    - IBV_TM_CAP_RC - Support tag matching on RC transport

