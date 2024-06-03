---
layout: page
title: HNSDV_QUERY_DEVICE
section: 3
tagline: Verbs
date: 2024-02-06
header: "HNS Direct Verbs Manual"
footer: hns
---

# NAME

hnsdv_query_device - Query hns device specific attributes

# SYNOPSIS

```c
#include <infiniband/hnsdv.h>
int hnsdv_query_device(struct ibv_context *context,
					   struct hnsdv_context *attrs_out);
```

# DESCRIPTION

**hnsdv_query_device()** Queries hns device specific attributes.

# ARGUMENTS

Please see *ibv_query_device(3)* man page for *context*.

## attrs_out

```c
struct hnsdv_context {
        uint64_t comp_mask;
        uint64_t flags;
        uint8_t congest_type;
        uint8_t reserved[7];
};
```

*comp_mask*
:	Bitmask specifying what fields in the structure are valid:

	HNSDV_CONTEXT_MASK_CONGEST_TYPE:
		Congestion control algorithm is supported.

*congest_type*
:	Bitmask of supported congestion control algorithms.

	HNSDV_QP_CREATE_ENABLE_DCQCN:
		Data Center Quantized Congestion Notification
	HNSDV_QP_CREATE_ENABLE_LDCP:
		Low Delay Control Protocol
	HNSDV_QP_CREATE_ENABLE_HC3:
		Huawei Converged Congestion Control
	HNSDV_QP_CREATE_ENABLE_DIP:
	    Destination IP based Quantized Congestion Notification

# RETURN VALUE

**hnsdv_query_device()** returns 0 on success, or the value of errno on failure
(which indicates the failure reason).

# SEE ALSO

**ibv_query_device**(3)

# NOTES

* *flags* is an out field and currently has no values.

# AUTHORS

Junxian Huang <huangjunxian6@hisilicon.com>
