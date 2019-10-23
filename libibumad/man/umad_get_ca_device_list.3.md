
---
date: "May 1, 2018"
footer: "OpenIB"
header: "OpenIB Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: UMAD_GET_CA_DEVICE_LIST
---

# NAME

umad_get_ca_device_list - get list of available InfiniBand device names.

# SYNOPSIS

```c
#include <infiniband/umad.h>

struct umad_device_node *umad_get_ca_device_list(void);
```

# DESCRIPTION

**umad_get_ca_device_list()**  fills the cas list of *struct umad_device_node*
with local IB devices (CAs) names.

*struct umad_device_node* is defined as follows:

```c
struct umad_device_node {
	struct umad_device_node *next;
	const char *ca_name;
};
```

# RETURN VALUE

**umad_get_ca_device_list()** returns list of *struct umad_device_node* filled
with local IB devices(CAs) names.
In case of empty list (zero elements), NULL is returned and
*errno* is not set.
On error, NULL is returned and *errno* is set appropriately.
The last value of the list is NULL in order to indicate the number of
entries filled.

# ERRORS

**umad_get_ca_device_list()** can fail with the following errors:

**ENOMEM**

# SEE ALSO

**umad_get_ca_portguids**(3), **umad_open_port**(3),
**umad_free_ca_device_list**

# AUTHORS

Vladimir Koushnir <vladimirk@mellanox.com>,
Hal Rosenstock <hal@mellanox.com>,
Haim Boozaglo <haimbo@mellanox.com>
