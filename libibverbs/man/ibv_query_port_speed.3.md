---
date: 2025-10-19
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: ibv_query_port_speed
---

# NAME

ibv_query_port_speed - query an RDMA port's effective bandwidth in 100Mb/s granularity

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_query_port_speed(struct ibv_context *context, uint32_t port_num, uint64_t *port_speed);

```


# DESCRIPTION

**ibv_query_port_speed()** Queries the device of the context at the given port number
for the effective bandwidth of the port in 100Mb/s granularity.

# ARGUMENTS
*context*
:       The device context.

*port_num*
:       The device port number which needs to be queried.

*port_speed*
:   The effective bandwidth of port for device context in a granularity of 100 Mb/s

# RETURN VALUE

**ibv_query_port_speed()** Returns 0 on success, or the value of errno on failure (which indicates the failure reason)

# NOTES

port_speed pointer value is valid only when the function returns 0.

# SEE ALSO

**ibv_query_port**(3)

# AUTHOR

Patrisious Haddad <phaddad@nvidia.com>
Or Har-Toov <ohartoov@nvidia.com>
