---
date: 2012-03-31
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_RATE_TO_MBPS
---

# NAME

ibv_rate_to_mbps - convert IB rate enumeration to Mbit/sec

mbps_to_ibv_rate - convert Mbit/sec to an IB rate enumeration

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_rate_to_mbps(enum ibv_rate rate);

enum ibv_rate mbps_to_ibv_rate(int mbps);
```

# DESCRIPTION

**ibv_rate_to_mbps()** converts the IB transmission rate enumeration *rate* to
a number of Mbit/sec. For example, if *rate* is **IBV_RATE_5_GBPS**, the
value 5000 will be returned (5 Gbit/sec = 5000 Mbit/sec).

**mbps_to_ibv_rate()** converts the number of Mbit/sec *mult* to an IB
transmission rate enumeration. For example, if *mult* is 5000, the rate
enumeration **IBV_RATE_5_GBPS** will be returned.

# RETURN VALUE

**ibv_rate_to_mbps()** returns the number of Mbit/sec.

**mbps_to_ibv_rate()** returns the enumeration representing the IB
transmission rate.

# SEE ALSO

**ibv_query_port**(3)

# AUTHOR

Dotan Barak <dotanb@dev.mellanox.co.il>
