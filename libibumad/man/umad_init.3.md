
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

**umad_init()** and **umad_done()** do nothing.

# RETURN VALUE

Always 0.

# COMPATIBILITY

Versions prior to release 18 of the library require **umad_init()** to be
called prior to using any other library functions. Old versions could return a
failure code of -1 from **umad_init()**.

For compatibility, applications should continue to call **umad_init()**, and
check the return code, prior to calling other **umad_** functions.  If
**umad_init()** returns an error, then no further use of the umad library
should be attempted.

# AUTHORS

Dotan Barak <dotanb@mellanox.co.il>,
Hal Rosenstock <halr@voltaire.com>
