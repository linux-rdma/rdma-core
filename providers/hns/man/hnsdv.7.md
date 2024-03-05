---
layout: page
title: HNSDV
section: 7
tagline: Verbs
date: 2024-02-06
header: "HNS Direct Verbs Manual"
footer: hns
---

# NAME

hnsdv \- Direct verbs for hns devices

This provides low level access to hns devices to perform direct operations,
without general branching performed by libibverbs.

# DESCRIPTION
The libibverbs API is an abstract one. It is agnostic to any underlying
provider specific implementation. While this abstraction has the advantage
of user applications portability it has a performance penalty. Besides,
some provider specific features that are directly facing users are not
available through libibverbs. For some applications these demands are more
important than portability.

The hns direct verbs API is intended for such applications.
It exposes hns specific low level operations, allowing the application
to bypass the libibverbs API and enable some hns specific features.

The direct include of hnsdv.h together with linkage to hns library will allow
usage of this new interface.

# SEE ALSO
**verbs**(7)

# AUTHORS

Junxian Huang <huangjunxian6@hisilicon.com>
