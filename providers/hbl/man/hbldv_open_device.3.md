---
layout: page
title: hbldv_open_device
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_open_device - Open an RDMA device context for the hbl provider

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

struct ibv_context *hbldv_open_device(struct ibv_device *device,
				      struct hbldv_ucontext_attr *attr);
```

# DESCRIPTION

Open an RDMA device context with specific hbl provider attributes.

# ARGUMENTS

*device*
:	RDMA device to open.

## *attr* argument

```c
struct hbldv_ucontext_attr {
	uint64_t ports_mask;
	int core_fd;
};
```

*ports_mask*
:	Mask of the relevant ports for this context. As all port numbers are
	non zero, mask should also be 1 based i.e. 0th bit is reserved.

*core_fd*
:	Core device file descriptor.

# RETURN VALUE

Returns a pointer to the allocated device context, or NULL if the request fails.

# SEE ALSO

**hbldv**(7), **ibv_open_device**(3)

# AUTHOR

Omer Shpigelman <oshpigelman@habana.ai>
