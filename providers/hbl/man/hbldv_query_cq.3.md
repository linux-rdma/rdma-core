---
layout: page
title: hbldv_query_cq
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_query_cq - Query proprietary CQ attributes

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

int hbldv_query_cq(struct ibv_context *context, hbldv_query_cq_attr *cq_attr);
```

# DESCRIPTION

**hbldv_query_cq** queries a CQ object for hbl provider specific CQ attributes.

# ARGUMENTS

*context*
:	RDMA device context to work on.

## *cq_attr*
:	Stores the provider specific CQ attributes.

```c
struct hbldv_query_cq_attr {
	struct ibv_cq *ibvcq;
	void *mem_cpu_addr;
	void *pi_cpu_addr;
	void *regs_cpu_addr;
	uint32_t cq_size;
	uint32_t cq_num;
	uint32_t regs_offset;
	enum hbldv_cq_type cq_type;
};
```
*mem_cpu_addr*
:	CC CQ memory mmap address.

*pi_cpu_addr*
:	CC CQ PI mmap address.

*regs_cpu_addr*
:	CQ objects mmap hardware address.

*cq_size*
:	CQ entry size.

*cq_num*
:	Number of CQ elements allocated.

*regs_offset*
:	CQ objects mmap hardware address reg offset.

*cq_type*
:	Type of CQ resource:

	HBLDV_CQ_TYPE_QP
		Standard CQ used for completion of a operation for a QP.

	HBLDV_CQ_TYPE_CC
		Congestion control CQ.

# RETURN VALUE

Returns a 0 on success, or the value of errno on failure.

# SEE ALSO

**hbldv**(7), **hbldv_create_cq**(3)

# AUTHOR

Bharat Jauhari <bjauhari@habana.ai>
