---
layout: page
title: hbldv_modify_qp
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_modify_qp - Manage state transitions for QP

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

int hbldv_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr,
		    int attr_mask, struct hbldv_qp_attr *hbl_attr);
```
# DESCRIPTION

Modify QP state with proprietary configuration data as defined in
*struct hbldv_qp_attr*.

# ARGUMENTS

*ibqp*
:	Pointer to QP object.

*attr*
:	Pointer to QP attributes

*attr_mask*
:	Attribute mask as defined in enum *ibv_qp_attr_mask* for QP updates.

## *hbl_attr*
:	hbl specific QP attributes.

```c
struct hbldv_qp_attr {
	uint64_t caps;
	uint32_t local_key;
	uint32_t remote_key;
	uint32_t congestion_wnd;
	uint32_t reserved0;
	uint32_t dest_wq_size;
	enum hbldv_qp_wq_types wq_type;
	enum hbldv_swq_granularity wq_granularity;
	uint8_t priority;
	uint8_t reserved1;
	uint8_t reserved2;
	uint8_t encap_num;
	uint8_t reserved3;
};
```

*caps*
:	QP capabilities bit-mask from *enum hbldv_qp_caps*.

*local_key*
:	Unique key for local memory access. Needed for RTR state.

*remote_key*
:	Unique key for remote memory access. Needed for RTS state.

*congestion_wnd*
:	Congestion-Window size. Needed for RTS state.

*dest_wq_size*
:	Number of WQEs on the destination. Needed for RDV RTS state.

*wq_type*
:	WQ type. e.g. write, rdv etc. Needed for INIT state.

*wq_granularity*
:	WQ granularity [0 for 32B or 1 for 64B]. Needed for INIT state.

*priority*
:	QoS priority. Needed for RTR and RTS state.

*encap_num*
:	Encapsulation ID. Needed for RTS and RTS state.

# NOTES

To use the full capability of the hardware , user needs to use the hbldv API for
QP state transition.

# RETURN VALUE

Returns 0 on success, or the value of errno on failure.

# SEE ALSO

**hbldv**(7), **hbldv_query_qp**(3)

# AUTHOR

Bharat Jauhari <bjauhari@habana.ai>
