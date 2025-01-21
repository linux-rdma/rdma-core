# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2024 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.mr cimport DmaBufMR

cdef class Mlx5DmaBufMR(DmaBufMR):
    pass
