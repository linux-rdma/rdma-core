# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file
"""
This module wraps mlx5dv_<obj> C structs, such as mlx5dv_cq, mlx5dv_qp etc.
It exposes to the users the mlx5 driver-specific attributes for ibv objects by
extracting them via mlx5dv_init_obj() API by using Mlx5DvObj class, which holds
all the (currently) supported Mlx5Dv<Obj> objects.
Note: This is not be confused with Mlx5<Obj> which holds the ibv_<obj>_ex that
      was created using mlx5dv_create_<obj>().
"""

from libc.stdint cimport uintptr_t, uint32_t

from pyverbs.pyverbs_error import PyverbsUserError, PyverbsRDMAError
cimport pyverbs.providers.mlx5.mlx5dv_enums as dve
cimport pyverbs.libibverbs as v


cdef class Mlx5DvPD(PyverbsObject):

    @property
    def pdn(self):
        """ The protection domain object number """
        return self.dv_pd.pdn

    @property
    def comp_mask(self):
        return self.dv_pd.comp_mask


cdef class Mlx5DvCQ(PyverbsObject):

    @property
    def cqe_size(self):
        return self.dv_cq.cqe_size

    @property
    def comp_mask(self):
        return self.dv_cq.comp_mask

    @property
    def cqn(self):
        return self.dv_cq.cqn

    @property
    def buf(self):
        return <uintptr_t><void*>self.dv_cq.buf

    @property
    def cq_uar(self):
        return <uintptr_t><void*>self.dv_cq.cq_uar

    @property
    def dbrec(self):
        return <uintptr_t><uint32_t*>self.dv_cq.dbrec

    @property
    def cqe_cnt(self):
        return self.dv_cq.cqe_cnt


cdef class Mlx5DvQP(PyverbsObject):

    @property
    def rqn(self):
        """ The receive queue number of the QP"""
        return self.dv_qp.rqn

    @property
    def sqn(self):
        """ The send queue number of the QP"""
        return self.dv_qp.sqn

    @property
    def tirn(self):
        """
        The number of the transport interface receive object that attached
        to the RQ of the QP
        """
        return self.dv_qp.tirn

    @property
    def tisn(self):
        """
        The number of the transport interface send object that attached
        to the SQ of the QP
        """
        return self.dv_qp.tisn

    @property
    def comp_mask(self):
        return self.dv_qp.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.dv_qp.comp_mask = val

    @property
    def uar_mmap_offset(self):
        return self.uar_mmap_offset


cdef class Mlx5DvSRQ(PyverbsObject):

    @property
    def stride(self):
        return self.dv_srq.stride

    @property
    def head(self):
        return self.dv_srq.stride

    @property
    def tail(self):
        return self.dv_srq.stride

    @property
    def comp_mask(self):
        return self.dv_srq.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.dv_srq.comp_mask = val

    @property
    def srqn(self):
        """ The shared receive queue object number """
        return self.dv_srq.srqn


cdef class Mlx5DvObj(PyverbsObject):
    """
    Mlx5DvObj represents mlx5dv_obj C struct.
    """
    def __init__(self, obj_type=None, **kwargs):
        """
        Retrieves DV objects from ibv object to be able to extract attributes
        (such as cqe_size of a CQ).
        Currently supports CQ, QP, PD and SRQ objects.
        The initialized objects can be accessed using self.dvobj (e.g. self.dvcq).
        :param obj_type: Bitmask which defines what objects was provided.
                         Currently it supports: MLX5DV_OBJ_CQ, MLX5DV_OBJ_QP,
                         MLX5DV_OBJ_SRQ and MLX5DV_OBJ_PD.
        :param kwargs: List of objects (cq, qp, pd, srq) from which to extract
                       data and their comp_masks if applicable. If comp_mask is
                       not provided by user, mask all by default.
        """
        self.dv_pd = self.dv_cq = self.dv_qp = self.dv_srq = None
        if obj_type is None:
            return
        self.init_obj(obj_type, **kwargs)

    def init_obj(self, obj_type, **kwargs):
        """
        Initialize DV objects.
        The objects are re-initialized if they're already extracted.
        """
        supported_obj_types = dve.MLX5DV_OBJ_CQ | dve.MLX5DV_OBJ_QP | \
                         dve.MLX5DV_OBJ_PD | dve.MLX5DV_OBJ_SRQ
        if obj_type & supported_obj_types is False:
            raise PyverbsUserError('Invalid obj_type was provided')

        cq = kwargs.get('cq') if obj_type | dve.MLX5DV_OBJ_CQ else None
        qp = kwargs.get('qp') if obj_type | dve.MLX5DV_OBJ_QP else None
        pd = kwargs.get('pd') if obj_type | dve.MLX5DV_OBJ_PD else None
        srq = kwargs.get('srq') if obj_type | dve.MLX5DV_OBJ_SRQ else None
        if cq is qp is pd is srq is None:
            raise PyverbsUserError("No supported object was provided.")

        if cq:
            dv_cq = Mlx5DvCQ()
            self.obj.cq.in_ = <v.ibv_cq*>cq.cq
            self.obj.cq.out = &(dv_cq.dv_cq)
            self.dv_cq = dv_cq
        if qp:
            dv_qp = Mlx5DvQP()
            comp_mask = kwargs.get('qp_comp_mask')
            dv_qp.comp_mask = comp_mask if comp_mask else \
                dv.MLX5DV_QP_MASK_UAR_MMAP_OFFSET | \
                dv.MLX5DV_QP_MASK_RAW_QP_HANDLES | \
                dv.MLX5DV_QP_MASK_RAW_QP_TIR_ADDR
            self.obj.qp.in_ = <v.ibv_qp*>qp.qp
            self.obj.qp.out = &(dv_qp.dv_qp)
            self.dv_qp = dv_qp
        if pd:
            dv_pd = Mlx5DvPD()
            self.obj.pd.in_ = <v.ibv_pd*>pd.pd
            self.obj.pd.out = &(dv_pd.dv_pd)
            self.dv_pd = dv_pd
        if srq:
            dv_srq = Mlx5DvSRQ()
            comp_mask = kwargs.get('srq_comp_mask')
            dv_srq.comp_mask = comp_mask if comp_mask else dv.MLX5DV_SRQ_MASK_SRQN
            self.obj.srq.in_ = <v.ibv_srq*>srq.srq
            self.obj.srq.out = &(dv_srq.dv_srq)
            self.dv_srq = dv_srq

        rc = dv.mlx5dv_init_obj(&self.obj, obj_type)
        if rc != 0:
            raise PyverbsRDMAError("Failed to initialize Mlx5DvObj", rc)

    @property
    def dvcq(self):
        return self.dv_cq

    @property
    def dvqp(self):
        return self.dv_qp

    @property
    def dvpd(self):
        return self.dv_pd

    @property
    def dvsrq(self):
        return self.dv_srq
