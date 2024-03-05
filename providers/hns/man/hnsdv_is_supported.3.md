---
layout: page
title: HNSDV_IS_SUPPORTED
section: 3
tagline: Verbs
date: 2024-02-06
header: "HNS Programmer's Manual"
footer: hns
---

# NAME

hnsdv_is_supported - Check whether an RDMA device implemented by the hns provider

# SYNOPSIS

```c
#include <infiniband/hnsdv.h>

bool hnsdv_is_supported(struct ibv_device *device);
```

# DESCRIPTION

hnsdv functions may be called only if this function returns true for the RDMA device.

# ARGUMENTS

*device*
:	RDMA device to check.

# RETURN VALUE
Returns true if device is implemented by hns provider.

# SEE ALSO

*hnsdv(7)*

# AUTHOR

Junxian Huang <huangjunxian6@hisilicon.com>
