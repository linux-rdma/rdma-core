---
layout: page
title: hnsdv_create_qp
section: 3
tagline: Verbs
date: 2021-07-13
header: "hns Programmer's Manual"
footer: hns
---

# NAME

hnsdv_create_qp - creates a queue pair (QP)

# SYNOPSIS

```c
#include <infiniband/hnsdv.h>

struct ibv_qp *hnsdv_create_qp(struct ibv_context *context,
			       struct ibv_qp_init_attr_ex *attr,
			       struct hnsdv_qp_init_attr *hns_attr)
```


# DESCRIPTION

**hnsdv_create_qp()** creates a queue pair (QP) with specific driver properties.

# ARGUMENTS

Please see *ibv_create_qp_ex(3)* man page for *context* and *attr*.

## hns_attr

```c
struct hnsdv_qp_init_attr {
	uint64_t comp_mask;
	uint32_t create_flags;
};
```

*comp_mask*
:	Bitmask specifying what fields in the structure are valid:
	HNSDV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS:
		valid values in *create_flags*

*create_flags*
:	A bitwise OR of the various values described below.

	HNSDV_QP_CREATE_DYNAMIC_CONTEXT_ATTACH :
		Enable DCA feature for QP, the WQE buffer will allocate
		from DCA memory pool when calling ibv_post_send() or
		ibv_post_recv().

# RETURN VALUE

**hnsdv_create_qp()**
returns a pointer to the created QP, on error NULL will be returned and errno will be set.

# SEE ALSO

**ibv_create_qp_ex**(3),

# AUTHOR

Xi Wang <wangxi11@huawei.com>

Weihang Li <liweihang@huawei.com>
