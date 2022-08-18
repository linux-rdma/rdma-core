# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

#cython: language_level=3

from pyverbs.base cimport PyverbsObject, PyverbsCM
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.device cimport Context
from pyverbs.pd cimport PD


cdef class Mlx5CryptoLoginAttr(PyverbsObject):
    cdef dv.mlx5dv_crypto_login_attr mlx5dv_crypto_login_attr

cdef class Mlx5CryptoExtLoginAttr(PyverbsObject):
    cdef dv.mlx5dv_crypto_login_attr_ex mlx5dv_crypto_login_attr_ex
    cdef object credential

cdef class Mlx5DEKInitAttr(PyverbsObject):
    cdef dv.mlx5dv_dek_init_attr mlx5dv_dek_init_attr
    cdef PD pd

cdef class Mlx5DEKAttr(PyverbsObject):
    cdef dv.mlx5dv_dek_attr mlx5dv_dek_attr

cdef class Mlx5CryptoAttr(PyverbsObject):
    cdef dv.mlx5dv_crypto_attr mlx5dv_crypto_attr

cdef class Mlx5DEK(PyverbsCM):
    cdef dv.mlx5dv_dek *mlx5dv_dek
    cdef PD pd

cdef class Mlx5CryptoLogin(PyverbsCM):
    cdef dv.mlx5dv_crypto_login_obj *crypto_login_obj
    cdef Context context
