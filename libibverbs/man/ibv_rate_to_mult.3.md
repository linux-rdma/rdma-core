---
date: 2006-10-31
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_RATE_TO_MULT
---

# NAME

ibv_rate_to_mult - convert IB rate enumeration to multiplier of 2.5 Gbit/sec

mult_to_ibv_rate - convert multiplier of 2.5 Gbit/sec to an IB rate
enumeration

# SYNOPSIS

```c
#include <infiniband/verbs.h>

int ibv_rate_to_mult(enum ibv_rate rate);

enum ibv_rate mult_to_ibv_rate(int mult);
```

# DESCRIPTION

**ibv_rate_to_mult()** converts the IB transmission rate enumeration *rate* to
a multiple of 2.5 Gbit/sec (the base rate). For example, if *rate* is
**IBV_RATE_5_GBPS**, the value 2 will be returned (5 Gbit/sec = 2 * 2.5
Gbit/sec).

**mult_to_ibv_rate()** converts the multiplier value (of 2.5 Gbit/sec) *mult*
to an IB transmission rate enumeration. For example, if *mult* is 2, the rate
enumeration **IBV_RATE_5_GBPS** will be returned.

# RETURN VALUE

**ibv_rate_to_mult()** returns the multiplier of the base rate 2.5 Gbit/sec.

**mult_to_ibv_rate()** returns the enumeration representing the IB
transmission rate.

# SEE ALSO

**ibv_query_port**(3)

# AUTHOR

Dotan Barak <dotanba@gmail.com>
