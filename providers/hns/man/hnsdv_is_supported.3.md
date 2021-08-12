---
layout: page
title: hnsdv_is_supported
section: 3
tagline: Verbs
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

Xi Wang <wangxi11@huawei.com>
