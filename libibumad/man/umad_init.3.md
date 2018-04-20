---
date: "May 21, 2007"
footer: "OpenIB"
header: "OpenIB Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: UMAD_INIT
---

# NAME

umad_init, umad_done - perform library initialization and finalization

# SYNOPSIS

```c
#include <infiniband/umad.h>

int umad_init(void);

int umad_done(void);
```

# DESCRIPTION

**umad_init()** initializes the umad library for use. Must be called before
any other call to this library.

**umad_done()** finalizes the use of the umad library.

# RETURN VALUE

**umad_init()** and **umad_done()** return 0 on success, and -1 on error.
Error is returned from **umad_init()** if infiniband umad can't be opened, or
the abi version doesn't match. There are no errors currently returned by
**umad_done().**

# NOTES

If an error occurs during the library initialization, no further use of the
umad library should be attempted.

# AUTHORS

Dotan Barak <dotanb@mellanox.co.il>,
Hal Rosenstock <halr@voltaire.com>
