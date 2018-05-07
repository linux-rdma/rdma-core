---
date: 2006-10-31
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_EVENT_TYPE_STR
---

# NAME

ibv_event_type_str - Return string describing event_type enum value

ibv_node_type_str - Return string describing node_type enum value

ibv_port_state_str - Return string describing port_state enum value

# SYNOPSIS

```c
#include <infiniband/verbs.h>

const char *ibv_event_type_str(enum ibv_event_type event_type);

const char *ibv_node_type_str(enum ibv_node_type node_type);

const char *ibv_port_state_str(enum ibv_port_state port_state);
```

# DESCRIPTION

**ibv_node_type_str()** returns a string describing the node type enum value
*node_type*.

**ibv_port_state_str()** returns a string describing the port state enum value
*port_state*.

**ibv_event_type_str()** returns a string describing the event type enum value
*event_type*.

# RETURN VALUE

These functions return a constant string that describes the enum value passed
as their argument.

# AUTHOR

Roland Dreier <rolandd@cisco.com>
