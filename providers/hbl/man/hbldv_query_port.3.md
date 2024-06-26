---
layout: page
title: hbldv_query_port
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_query_port - Query non standard attributes of IB device port

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

int hbldv_query_port(struct ibv_context *context, uint32_t port_num,
		     struct hbldv_query_port_attr *hbl_attr);
```

# DESCRIPTION

Query port info which can be used for some device commands over the HBL device
interface and when directly accessing the hardware resources.

The API lets a user query different attributes related to the requested port.

# ARGUMENTS

*context*
:	RDMA device context to work on.

*port_num*
:	Port number to query.

## *hbl_attr*
:	Stores the returned attributes from the kernel.

```c
struct hbldv_query_port_attr {
	uint32_t max_num_of_qps;
	uint32_t num_allocated_qps;
	uint32_t max_allocated_qp_num;
	uint32_t max_cq_size;
	uint32_t reserved0;
	uint32_t reserved1;
	uint32_t reserved2;
	uint32_t reserved3;
	uint32_t reserved4;
	uint8_t advanced;
	uint8_t max_num_of_cqs;
	uint8_t max_num_of_usr_fifos;
	uint8_t max_num_of_encaps;
	uint8_t nic_macro_idx;
	uint8_t nic_phys_port_idx;
};
```

*max_num_of_qps*
:	Maximum number of QPs that are supported by the driver. User must
	allocate enough room for its work-queues according to this number.

*num_allocated_qps*
:	Number of QPs that were already allocated (in use).

*max_allocated_qp_num*
:	The highest index of the allocated QPs (i.e. this is where the driver
	may allocate its next QP).

*max_cq_size*
:	Maximum size of a CQ buffer.
*advanced*
:	True if advanced features are supported.

*max_num_of_cqs*
:	Maximum number of CQs.

*max_num_of_usr_fifos*
:	Maximum number of user FIFOs.

*max_num_of_encaps*
:	Maximum number of encapsulations.

*nic_macro_idx*
:	Nacro index of this specific port.

*nic_phys_port_idx*
:	Physical port index (AKA lane) of this specific port.

# NOTES

A user should provide the port number to query. On successful query, the
attributes as defined in the *struct hbldv_query_port_attr* will be returned
for the requested port.

External ports connected to a switch are referred to as scale-out. Ports
connected within itself internally are referred to as scale-up ports.

# RETURN VALUE

Returns 0 on success, or the value of errno on failure.

# EXAMPLE

```c
struct hbldv_query_port_attr port_attr = {};

for (port = 1; port < max_n_ports; port++) {
	rc = hbldv_query_port(context, port, &port_attr);

	printf("Port:%u Current allocated QPs:%u\n", port, port_attr.num_allocated_qps);
	printf("Port:%u Lane:%u\n", port, port_attr.nic_phys_port_idx);
}
```

# SEE ALSO

**hbldv**(7), **hbldv_query_device**(3)

# AUTHOR

Abhilash K V <kvabhilash@habana.ai>
