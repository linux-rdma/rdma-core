---
layout: page
title: EFADV_QUERY_DEVICE
section: 3
tagline: Verbs
date: 2019-04-22
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv_query_device - Query device capabilities

# SYNOPSIS

```c
#include <infiniband/efadv.h>

int efadv_query_device(struct ibv_context *ibvctx,
		       struct efadv_device_attr *attr,
		       uint32_t inlen);
```

# DESCRIPTION

**efadv_query_device()** Queries EFA device specific attributes.

Compatibility is handled using the comp_mask and inlen fields.

```c
struct efadv_device_attr {
	uint64_t comp_mask;
	uint32_t max_sq_wr;
	uint32_t max_rq_wr;
	uint16_t max_sq_sge;
	uint16_t max_rq_sge;
	uint16_t inline_buf_size;
	uint16_t inline_buf_size_ex;
	uint32_t device_caps;
	uint32_t max_rdma_size;
	uint32_t max_comp_actions;
	uint32_t comp_action_supp_ops;
};
```

*inlen*
:	In: Size of struct efadv_device_attr.

*comp_mask*
:	Compatibility mask.

*max_sq_wr*
:	Maximum Send Queue (SQ) Work Requests (WRs).

*max_rq_wr*
:	Maximum Receive Queue (RQ) Work Requests (WRs).

*max_sq_sge*
:	Maximum Send Queue (SQ) Scatter Gather Elements (SGEs).

*max_rq_sge*
:	Maximum Receive Queue (RQ) Scatter Gather Elements (SGEs).

*inline_buf_size*
:	Maximum inline buffer size (deprecated by inline_buf_size_ex).

*inline_buf_size_ex*
:	Maximum inline buffer size.

*device_caps*
:	Bitmask of device capabilities:

	EFADV_DEVICE_ATTR_CAPS_RDMA_READ:
		RDMA read is supported.

	EFADV_DEVICE_ATTR_CAPS_RNR_RETRY:
		RNR retry is supported for SRD QPs.

	EFADV_DEVICE_ATTR_CAPS_CQ_WITH_SGID:
		Reading source address (SGID) from receive completion descriptors is supported.
		Valid only for unknown AH.

	EFADV_DEVICE_ATTR_CAPS_RDMA_WRITE:
		RDMA write is supported

	EFADV_DEVICE_ATTR_CAPS_UNSOLICITED_WRITE_RECV:
		Indicates the device has support for creating QPs that can receive unsolicited
		RDMA write with immediate. RQ with this feature enabled will not consume any work
		requests in order to receive RDMA write with immediate and a WC generated for such
		receive will be marked as unsolicited.

	EFADV_DEVICE_ATTR_CAPS_CQ_WITH_EXT_MEM_DMABUF:
		Indicates that creating CQs with external memory buffers by passing dmabuf is
		supported.

	EFADV_DEVICE_ATTR_CAPS_COMP_CNTR:
		Completion counters are supported.

	EFADV_DEVICE_ATTR_CAPS_COMP_ACTION:
		QPs can be created with completion action wr_flags,
		see **efadv_create_qp_ex**(3).

*max_rdma_size*
:	Maximum RDMA transfer size in bytes.

*max_comp_actions*
:	Maximum number of completion actions.

*comp_action_supp_ops*
:	Bitmask indicating which completion events can trigger completion
	actions:

	EFADV_DEVICE_ATTR_COMP_ACTION_SUPPORTED_OP_SEND:
		Send completion.

	EFADV_DEVICE_ATTR_COMP_ACTION_SUPPORTED_OP_RECV:
		Receive completion.

	EFADV_DEVICE_ATTR_COMP_ACTION_SUPPORTED_OP_RDMA_READ:
		RDMA read initiator completion.

	EFADV_DEVICE_ATTR_COMP_ACTION_SUPPORTED_OP_REMOTE_RDMA_READ:
		RDMA read target (responder) completion.

	EFADV_DEVICE_ATTR_COMP_ACTION_SUPPORTED_OP_RDMA_WRITE:
		RDMA write initiator completion.

	EFADV_DEVICE_ATTR_COMP_ACTION_SUPPORTED_OP_REMOTE_RDMA_WRITE:
		RDMA write target completion.

	EFADV_DEVICE_ATTR_COMP_ACTION_SUPPORTED_OP_REMOTE_RDMA_WRITE_IMM:
		RDMA write with immediate target completion.

# RETURN VALUE

**efadv_query_device()** returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# SEE ALSO

**efadv**(7)

# NOTES

* Compatibility mask (comp_mask) is an out field and currently has no values.

# AUTHORS

Gal Pressman <galpress@amazon.com>
