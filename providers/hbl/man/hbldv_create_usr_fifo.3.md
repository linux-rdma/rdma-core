---
layout: page
title: hbldv_create_usr_fifo
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_create_usr_fifo - Allocate h/w resource to send commands to NICs

hbldv_destroy_usr_fifo - Free previously allocated h/w resource

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

struct hbldv_usr_fifo *hbldv_create_usr_fifo(struct ibv_context *context,
					     struct hbldv_usr_fifo_attr *attr);

int hbldv_destroy_usr_fifo(struct hbldv_usr_fifo *usr_fifo);
```

# DESCRIPTION

Create/destroy a hardware resource to allow user to send direct commands to NIC.
The resource is allocated per port.

# ARGUMENTS

*context*
:	RDMA device context to work on.

## *attr*
:	Input attributes while requesting for a hardware resource.

```c
struct hbldv_usr_fifo_attr {
	uint32_t port_num;
	uint32_t reserved0;
	uint32_t reserved1;
	uint32_t usr_fifo_num_hint;
	enum hbldv_usr_fifo_type usr_fifo_type;
	uint8_t reserved2;
};
```

*port_num*
:	Port number.

*usr_fifo_num_hint*
:	Hint to allocate a specific usr_fifo HW resource.

*usr_fifo_type*
:	FIFO Operation mode:

	HBLDV_USR_FIFO_TYPE_DB
		Mode for direct user door-bell submit.

	HBLDV_USR_FIFO_TYPE_CC
		Mode for congestion control.

## *usr_fifo*
:	Hardware resource in action.

```c
struct hbldv_usr_fifo {
	void *ci_cpu_addr;
	void *regs_cpu_addr;
	uint32_t regs_offset;
	uint32_t usr_fifo_num;
	uint32_t size;
	uint32_t bp_thresh;
};
```

*ci_cpu_addr*
:	Consumer index's user virtual address.

*regs_cpu_addr*
:	User virtual address to the hardware resource.

*regs_offset*
:	The offset within the resource from where user can access the resource.

*usr_fifo_num*
:	FIFO resource ID.

*size*
:	Allocated fifo size.

*bp_thresh*
:	Back pressure threshold that was set by the driver.

# NOTES

On success user gets direct access to the resource using the information in
*hbldv_usr_fifo* structure. If *usr_fifo_num_hint* is non-zero, driver will try
to allocate the same resource. if not available, the API will return an error.

User should use *ci_cpu_addr* to synchronize its command execution.

# RETURN VALUE

**hbldv_create_usr_fifo()** returns a pointer to a new *struct hbldv_usr_fifo*
on success or NULL on failure.

**hbldv_destroy_usr_fifo()** returns 0 on success or the value of errno on
failure.

# SEE ALSO

**hbldv**(7)

# AUTHOR

Omer Shpigelman <oshpigelman@habana.ai>
