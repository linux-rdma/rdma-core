---
date: 2026-09-24
footer: libibmad
header: "Libibmad Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: SA_KEY_SET
---

# NAME

sa_key_set, sa_key_get - set or get the SM_Key used for SA requests

# SYNOPSIS

```c
#include <infiniband/mad.h>

void sa_key_set(struct ibmad_port *srcport, uint64_t key);

uint64_t sa_key_get(const struct ibmad_port *srcport);
```

# DESCRIPTION

**sa_key_set()** sets the Subnet Administration (SA) SM_Key associated with
*srcport*. Subsequent requests sent through **sa_rpc_call()**, including the
requests made by **ib_path_query_via()** and **ib_node_query_via()**, encode
*key* in the SM_Key field of the SA header.

An **ibmad_port** returned by **mad_rpc_open_port()** or
**mad_rpc_open_port2()** initially has an SA SM_Key of 0. This preserves the
untrusted-request behavior used when **sa_key_set()** is not called.

**sa_key_get()** returns the SA SM_Key currently associated with *srcport*.

The SA SM_Key is separate from the SMP M_Key configured by
**smp_mkey_set()**.

# RETURN VALUE

**sa_key_set()** has no return value.

**sa_key_get()** returns the configured SA SM_Key in host byte order.

# AUTHORS

Jonathan Süssemilch Poulain <jpoulain@coreweave.com>
