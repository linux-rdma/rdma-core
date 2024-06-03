---
layout: page
title: HNSDV_CREATE_QP
section: 3
tagline: Verbs
date: 2024-02-06
header: "HNS Programmer's Manual"
footer: hns
---

# NAME

hnsdv_create_qp - creates a HNS specific queue pair (QP)

# SYNOPSIS

```c
#include <infiniband/hnsdv.h>

struct ibv_qp *hnsdv_create_qp(struct ibv_context *context,
							   struct ibv_qp_init_attr_ex *qp_attr,
							   struct hnsdv_qp_init_attr *hns_attr);
```

# DESCRIPTION

**hnsdv_create_qp()** creates a HNS specific queue pair (QP) with specific driver properties.

# ARGUMENTS
Please see *ibv_create_qp_ex(3)* man page for *context* and *qp_attr*.

## hns_attr

```c
struct hnsdv_qp_init_attr {
        uint64_t comp_mask;
        uint32_t create_flags;
        uint8_t congest_type;
        uint8_t reserved[3];
};
```
*comp_mask*
:	Bitmask specifying what fields in the structure are valid:

```
HNSDV_QP_INIT_ATTR_MASK_QP_CONGEST_TYPE:
    Valid values in congest_type. Allow setting a congestion control algorithm for QP.
```

*create_flags*
:	Enable the QP of a feature.

*congest_type*
:   Type of congestion control algorithm:

    HNSDV_QP_CREATE_ENABLE_DCQCN:
        Data Center Quantized Congestion Notification
    HNSDV_QP_CREATE_ENABLE_LDCP:
        Low Delay Control Protocol
    HNSDV_QP_CREATE_ENABLE_HC3:
        Huawei Converged Congestion Control
    HNSDV_QP_CREATE_ENABLE_DIP:
        Destination IP based Quantized Congestion Notification

# RETURN VALUE

**hnsdv_create_qp()**
returns a pointer to the created QP, on error NULL will be returned and errno will be set.

# SEE ALSO

**ibv_create_qp_ex**(3)

# AUTHOR

Junxian Huang <huangjunxian6@hisilicon.com>
