---
layout: page
title: hbldv_query_qp
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_query_qp - Query proprietary QP attributes

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

int hbldv_query_qp(struct ibv_qp *ibvqp, struct hbldv_query_qp_attr *qp_attr);

```

# DESCRIPTION

This API is needed to get access to the hardware specific QP attributes.

# ARGUMENTS

*ibqp*
:	Pointer to QP object.

## *qp_attr*
:	Stores the returned QP attributes from the kernel.

```c
struct hbldv_query_qp_attr {
	uint32_t qp_num;
	void *swq_cpu_addr;
	void *rwq_cpu_addr;
};
```

*qp_num*
:	Hardware QP num.

*swq_cpu_addr*
:	Send WQ mmap address.

*rwq_cpu_addr*
:	Receive WQ mmap address.

# RETURN VALUE

Returns 0 on success, or the value of errno on failure.

# SEE ALSO

**hbldv**(7), **hbldv_modify_qp**(3)

# AUTHOR

Bharat Jauhari <bjauhari@habana.ai>
