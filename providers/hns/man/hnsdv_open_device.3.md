---
layout: page
title: hnsdv_open_device
section: 3
tagline: Verbs
---

# NAME

hnsdv_open_device - Open an RDMA device context for the hns provider

# SYNOPSIS

```c
#include <infiniband/hnsdv.h>

struct ibv_context *
hnsdv_open_device(struct ibv_device *device, struct hnsdv_context_attr *attr);
```

# DESCRIPTION

Open an RDMA device context with specific hns provider attributes.

# ARGUMENTS

*device*
:	RDMA device to open.

## *attr* argument

```c
struct hnsdv_context_attr {
	uint64_t flags;
	uint64_t comp_mask;
	uint32_t dca_prime_qps;
	uint32_t dca_unit_size;
	uint64_t dca_max_size;
	uint64_t dca_min_size;
};
```

*flags*
:       A bitwise OR of the various values described below.

        *HNSDV_CONTEXT_FLAGS_DCA*:
        Create a DCA memory pool to support all QPs share it.

*comp_mask*
:       Bitmask specifying what fields in the structure are valid

*dca_prime_qps*
:       The DCA status will sync by shared memory when DCA num is small than prime qps .

*dca_unit_size*
:       The unit size when adding a new buffer to DCA memory pool.

*dca_max_size*
:       The DCA pool will be expanded when the total size is smaller than maximal size.

*dca_min_size*
:       The DCA pool will be shrunk when the free size is bigger than minimal size.

# RETURN VALUE

Returns a pointer to the allocated device context, or NULL if the request fails.

# SEE ALSO

*hnsdv_create_qp(3)*, *hns_dca(7)*

# AUTHOR

Xi Wang <wangxi11@huawei.com>
