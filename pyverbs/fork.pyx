# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2021 Amazon.com, Inc. or its affiliates. All rights reserved.

#cython: language_level=3

from pyverbs.base import PyverbsRDMAError
cimport pyverbs.libibverbs as v


def fork_init():
    ret = v.ibv_fork_init()
    if ret:
        raise PyverbsRDMAError('Failed to init fork support', ret)


def is_fork_initialized():
    return v.ibv_is_fork_initialized()
