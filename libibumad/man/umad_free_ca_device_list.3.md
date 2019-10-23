
---
date: "May 1, 2018"
footer: "OpenIB"
header: "OpenIB Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: UMAD_FREE_CA_DEVICE_LIST
---

# NAME

umad_free_ca_device_list - free InfiniBand devices name list

# SYNOPSIS

```c
#include <infiniband/umad.h>

void umad_free_ca_device_list(struct umad_device_node *head);
```

# DESCRIPTION

**umad_free_ca_device_list()** frees the *struct umad_device_node*
list and its values that allocated with umad_get_ca_namelist().
The argument head is list of *struct umad_device_node* filled with
local IB devices(CAs) names.

# RETURN VALUE

**umad_free_ca_device_list()** returns no value.

# SEE ALSO

**umad_get_ca_device_list**

# AUTHORS

Vladimir Koushnir <vladimirk@mellanox.com>,
Hal Rosenstock <hal@mellanox.com>,
Haim Boozaglo <haimbo@mellanox.com>
