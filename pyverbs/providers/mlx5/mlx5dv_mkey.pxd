# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.pd cimport PD

cdef class Mlx5MkeyConfAttr(PyverbsObject):
    cdef dv.mlx5dv_mkey_conf_attr mlx5dv_mkey_conf_attr

cdef class Mlx5MrInterleaved(PyverbsObject):
    cdef dv.mlx5dv_mr_interleaved mlx5dv_mr_interleaved

cdef class Mlx5Mkey(PyverbsCM):
    cdef dv.mlx5dv_mkey *mlx5dv_mkey
    cdef PD pd
    cdef object max_entries

cdef class Mlx5SigCrc(PyverbsObject):
    cdef dv.mlx5dv_sig_crc mlx5dv_sig_crc

cdef class Mlx5SigT10Dif(PyverbsObject):
    cdef dv.mlx5dv_sig_t10dif mlx5dv_sig_t10dif

cdef class Mlx5SigBlockDomain(PyverbsObject):
    cdef dv.mlx5dv_sig_block_domain mlx5dv_sig_block_domain

cdef class Mlx5SigBlockAttr(PyverbsObject):
    cdef dv.mlx5dv_sig_block_attr mlx5dv_sig_block_attr

cdef class Mlx5SigErr(PyverbsObject):
    cdef dv.mlx5dv_sig_err mlx5dv_sig_err

cdef class Mlx5MkeyErr(PyverbsObject):
    cdef dv.mlx5dv_mkey_err mlx5dv_mkey_err
