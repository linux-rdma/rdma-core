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


### TM-SRQ creation

TM-SRQs are created by the ibv_create_srq_ex() Verb, which accepts the
following new attributes:
* **srq_type** - set to **IBV_SRQT_TM**
* **comp_mask** - set the **IBV_SRQ_INIT_ATTR_TM** flag
* **tm_cap** - TM properties for this TM-SRQ; defined as follows:

```h
struct ibv_tm_cap {
	 uint32_t max_num_tags;   /* Matching list size */
	 uint32_t max_ops;	  /* Number of outstanding TM operations */
}
```
Similarly to XRC SRQs, a TM-SRQ has a dedicated CQ.

RC QPs are associated with the TM-SRQ just like standard SRQs. However, the
ownership of the QP's Send Queue is passed to the TM-SRQ, which uses it to
initiate rendezvous RDMA-Reads. Receive completions are reported to the
TM-SRQ's CQ.


### Managing TM receive buffers

Untagged (unexpected) buffers are posted using the standard
**ibv_post_srq_recv**() Verb.

Tagged buffers are manipulated by a new **ibv_post_srq_ops**() Verb:

```h
int ibv_post_srq_ops(struct ibv_srq *srq, struct ibv_ops_wr *wr,
                     struct ibv_ops_wr **bad_wr);
```
```h
struct ibv_ops_wr {
	 uint64_t		 wr_id;    /* User defined WR ID */
	 /* Pointer to next WR in list, NULL if last WR */
	 struct ibv_ops_wr	*next;
	 enum ibv_ops_wr_opcode  opcode;   /* From enum ibv_ops_wr_opcode */
	 int			 flags;    /* From enum ibv_ops_flags */
	 struct {
		  /* Number of unexpected messages
		   * handled by SW */
		  uint32_t unexpected_cnt;
		  /* Input parameter for the DEL opcode
		   * and output parameter for the ADD opcode */
		  uint32_t handle;
		  struct {
			  /* WR ID for TM_RECV */
			  uint64_t		  recv_wr_id;
			  struct ibv_sge	 *sg_list;
			  int			  num_sge;
			  uint64_t		  tag;
			  uint64_t		  mask;
		  } add;
	 } tm;
};
```

The following opcodes are defined:

Opcode **IBV_WR_TAG_ADD** - add a tagged buffer entry to the tag matching list.
The input consists of an SGE list, a tag, a mask (matching parameters), and the
latest unexpected message count. A handle that uniquely identifies the entry is
returned upon success.

Opcode **IBV_WR_TAG_DEL** - delete a tag entry.
The input is an entry handle returned from a previous **IBV_WR_TAG_ADD**
operation, and the latest unexpected message count.

Note that the operation may fail if the associated tag was consumed by an
incoming message. In this case **IBV_WC_TM_ERR** status will be returned in WC.

Opcode **IBV_WR_TAG_SYNC** - report the number of unexpected messages handled by
the SW.
The input comprises only the unexpected message count. To reduce explicit
synchronization to a minimum, all completions indicate when synchronization is
necessary by setting the **IBV_WC_TM_SYNC_REQ** flag.

**ibv_post_srq_ops**() operations are non-signaled by default. To request an
explicit completion for a given operation, the standard **IBV_OPS_SIGNALED**
flag must be set. The number of outstanding tag-manipulation operations must
not exceed the **max_ops** capability.

While **wr_id** identifies the tag manipulation operation itself, the
**recv_wr_id** field is used to identify the tagged buffer in receive
completions.


### TM completion processing

There are 2 types of TM completions: tag-manipulation and receive completions.

Tag-manipulation operations generate the following completion opcodes:
* **IBV_WC_TM_ADD** - completion of a tag addition operation
* **IBV_WC_TM_DEL** - completion of a tag removal operation
* **IBV_WC_TM_SYNC** - completion of a synchronization operation

These completions are complemented by the **IBV_WC_TM_SYNC_REQ** flag, which
indicates whether further HW synchronization is needed.

