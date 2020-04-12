
---
date: "April 23, 2020"
footer: "OpenIB"
header: "OpenIB Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: UMAD_SORT_CA_DEVICE_LIST
---

# NAME

umad_sort_ca_device_list - sort list of InfiniBand device names in
alphabetical order.

# SYNOPSIS

```c
#include <infiniband/umad.h>

int umad_sort_ca_device_list(struct umad_device_node **head, size_t size);
```

# DESCRIPTION

**umad_sort_ca_device_list(struct umad_device_node **head, size_t size)**
sort the cas list of *struct umad_device_node* by IB devices (CAs) names
(Alphabetical sorting).
if *size_t size* input parameter is zero, the function will calculate the
size of the cas list.

*struct umad_device_node* is defined as follows:

```c
struct umad_device_node {
	struct umad_device_node *next;
	const char *ca_name;
};
```

# RETURN VALUE

**umad_sort_ca_device_list(struct umad_device_node **head, size_t size)**
returns zero value if sorting was succeded.
The function also returns pointer to list (struct umad_device_node **head)
sorted in alphabetical order as output parameter.
On error, non-zero value is returned.
*errno* is not set.

# SEE ALSO

**umad_get_ca_device_list**, **umad_free_ca_device_list**

# AUTHORS

Haim Boozaglo <haimbo@mellanox.com>
