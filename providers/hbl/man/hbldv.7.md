---
layout: page
title: HBLDV
section: 7
tagline: Verbs
date: 2024-05-03
header: "HabanaLabs DL accelerators Direct Verbs Manual"
footer: hbl
---

# NAME

hbldv - Direct verbs for ROCE links in HabanaLabs DL accelerators

This provides low level access to the DL accelerator's NICs to perform direct
operations, without general branching performed by libibverbs.

# DESCRIPTION

The libibverbs API is an abstract one. It is agnostic to any underlying
provider specific implementation. While this abstraction has the advantage
of user applications portability, it has a performance penalty. For some
applications optimizing performance is more important than portability.

The habanalabs direct verbs API is intended for such applications.
It exposes habanalabs specific hardware level features, allowing the application
to bypass the libibverbs API.

The direct include of hbldv.h together with linkage to hbl library will
allow usage of this new interface.

# SEE ALSO

**verbs**(7)

# AUTHORS

Bharat Jauhari <bjauhari@habana.ai>
