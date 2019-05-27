---
layout: page
title: EFADV
section: 7
tagline: Verbs
date: 2019-01-19
header: "EFA Direct Verbs Manual"
footer: efa
---

# NAME

efadv - Direct verbs for efa devices

This provides low level access to efa devices to perform direct operations,
without general branching performed by libibverbs.

# DESCRIPTION
The libibverbs API is an abstract one. It is agnostic to any underlying
provider specific implementation. While this abstraction has the advantage
of user applications portability, it has a performance penalty. For some
applications optimizing performance is more important than portability.

The efa direct verbs API is intended for such applications.
It exposes efa specific low level operations, allowing the application
to bypass the libibverbs API.

The direct include of efadv.h together with linkage to efa library will
allow usage of this new interface.

# SEE ALSO
**verbs**(7)

# AUTHORS

Gal Pressman <galpress@amazon.com>
