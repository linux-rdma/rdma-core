---
layout: page
title: hbldv_is_supported
section: 3
tagline: Verbs
date: 2024-05-03
header: "hbl Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv_is_supported - Check if an RDMA device is implemented by the hbl provider

# SYNOPSIS

```c
#include <infiniband/hbldv.h>

bool hbldv_is_supported(struct ibv_device *device);
```

# DESCRIPTION

hbldv functions can be used only if this function returns true for the given
RDMA device.

# ARGUMENTS

*device*
:	RDMA device to check.

# RETURN VALUE

Returns true if device is implemented by hbl provider, false otherwise.

# SEE ALSO

**hbldv**(7)

# AUTHOR

Omer Shpigelman <oshpigelman@habana.ai>
