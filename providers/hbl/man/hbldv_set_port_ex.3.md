---
layout: page
title: hbldv_set_port_ex
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_set_port_ex - Set properties for a particular port

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

int hbldv_set_port_ex(struct ibv_context *context,struct hbldv_port_ex_attr *attr);
```

# DESCRIPTION

The API configures several hardware related configurations per port as defined
in *struct hbldv_port_ex_attr*.

# ARGUMENTS

*context*
:	RDMA device context to work on.

## *attr*
:	Structure to define port related extended properties.

```c
struct hbldv_port_ex_attr {
	struct hbldv_wq_array_attr wq_arr_attr[HBLDV_WQ_ARRAY_TYPE_MAX];
	uint64_t caps;
	uint32_t qp_wq_bp_offs[HBLDV_USER_BP_OFFS_MAX];
	uint32_t reserved0[HBLDV_PORT_EX_ATTR_RESERVED0_NUM];
	uint32_t port_num;
	uint8_t reserved1;
};
```
## *wq_arr_attr*
:	Array of WQ-array attributes for each WQ-array type.

```c
struct hbldv_wq_array_attr {
	uint32_t max_num_of_wqs;
	uint32_t max_num_of_wqes_in_wq;
	enum hbldv_mem_id mem_id;
	enum hbldv_swq_granularity swq_granularity;
};
```

*max_num_of_wqs*
:	Max number of WQs (QPs) to be used.

*max_num_of_wqes_in_wq*
	Max number of WQ elements in each WQ.

*mem_id*
	Memory allocation method:

	HBLDV_MEM_HOST
		 Memory allocated on the host.

	HBLDV_MEM_DEVICE
		Memory allocated on the device.

*swq_granularity*
	Send WQE size.

*caps*
:	Port capabilities bit-mask:

	HBLDV_PORT_CAP_ADVANCED
		Enable port advanced features like RDV, QMan, WTD, etc.

	HBLDV_PORT_CAP_ADAPTIVE_TIMEOUT
		Enable adaptive timeout feature on this port.

*qp_wq_bp_offs*
:	Offsets in NIC memory to signal a back pressure.

*port_num*
:	Port number.

# NOTES

The user will need to call it for each port to be used after the device open but
before any network operations.

# RETURN VALUE

Returns 0 on success, or the value of errno on failure.

# SEE ALSO

**hbldv**(7), **hbldv_query_port**(3)

# AUTHOR

Sagiv Ozeri <sozeri@habana.ai>
