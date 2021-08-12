# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 HiSilicon Limited. All rights reserved.

#cython: language_level=3

cdef extern from 'infiniband/hnsdv.h':

    cpdef enum hnsdv_context_attr_flags:
        HNSDV_CONTEXT_FLAGS_DCA	= 1 << 0

    cpdef enum hnsdv_context_comp_mask:
        HNSDV_CONTEXT_MASK_DCA_PRIME_QPS	= 1 << 0
        HNSDV_CONTEXT_MASK_DCA_UNIT_SIZE	= 1 << 1
        HNSDV_CONTEXT_MASK_DCA_MAX_SIZE		= 1 << 2
        HNSDV_CONTEXT_MASK_DCA_MIN_SIZE		= 1 << 3

    cpdef enum hnsdv_qp_init_attr_mask:
        HNSDV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS	= 1 << 0

    cpdef enum hnsdv_qp_create_flags:
        HNSDV_QP_CREATE_ENABLE_DCA_MODE		= 1 << 0
