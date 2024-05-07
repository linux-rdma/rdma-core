# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2022-2024 HabanaLabs, Ltd.
# Copyright (C) 2023-2024, Intel Corporation.
# All Rights Reserved.

#cython: language_level=3

cdef extern from 'infiniband/hbldv.h':

    cpdef enum hbldv_mem_id:
        HBLDV_MEM_HOST   = 1
        HBLDV_MEM_DEVICE = 2

    cpdef enum hbldv_swq_granularity:
        HBLDV_SWQE_GRAN_32B = 0
        HBLDV_SWQE_GRAN_64B = 1

    cpdef enum hbldv_qp_wq_types:
        HBLDV_WQ_WRITE = 0x1
        HBLDV_WQ_RECV_RDV = 0x2
        HBLDV_WQ_READ_RDV = 0x4
        HBLDV_WQ_SEND_RDV = 0x8
        HBLDV_WQ_READ_RDV_ENDP = 0x10

    cpdef enum hbldv_usr_fifo_type:
        HBLDV_USR_FIFO_TYPE_DB = 0
        HBLDV_USR_FIFO_TYPE_CC = 1

    cpdef enum hbldv_cq_type:
        HBLDV_CQ_TYPE_QP = 0
        HBLDV_CQ_TYPE_CC = 1

    cpdef enum hbldv_encap_type:
        HBLDV_ENCAP_TYPE_NO_ENC = 0
        HBLDV_ENCAP_TYPE_ENC_OVER_IPV4 = 1
        HBLDV_ENCAP_TYPE_ENC_OVER_UDP = 2

    cpdef enum hbldv_device_attr_caps:
        HBLDV_DEVICE_ATTR_CAP_CC = 1 << 0
