---
date: 2020-10-09
footer: libibverbs
header: "Libibverbs Programmer's Manual"
layout: page
license: 'Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md'
section: 3
title: IBV_IS_FORK_INITIALIZED
---

# NAME

ibv_is_fork_initialized - check if fork support (ibv_fork_init) is enabled

# SYNOPSYS

```c
#include <infiniband/verbs.h>

enum ibv_fork_status {
	IBV_FORK_DISABLED,
	IBV_FORK_ENABLED,
	IBV_FORK_UNNEEDED,
};

enum ibv_fork_status ibv_is_fork_initialized(void);
```

# DESCRIPTION

**ibv_is_fork_initialized()** checks whether libibverbs **fork()** support was
enabled through the **ibv_fork_init()** verb.

# RETURN VALUE

**ibv_is_fork_initialized()** returns IBV_FORK_DISABLED if fork support is
disabled, or IBV_FORK_ENABLED if enabled. IBV_FORK_UNNEEDED return value
indicates that the kernel copies DMA pages on fork, hence a call to
**ibv_fork_init()** is unneeded.

# SEE ALSO

**fork**(2),
**ibv_fork_init**(3)

# AUTHOR

Gal Pressman <galpress@amazon.com>
