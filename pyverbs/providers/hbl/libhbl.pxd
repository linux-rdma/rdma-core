# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2022-2024 HabanaLabs, Ltd.
# Copyright (C) 2023-2024, Intel Corporation.
# All Rights Reserved.

#cython: language_level=3

include 'hbl_enums.pxd'

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, uintptr_t
from posix.types cimport off_t
from libcpp cimport bool

cimport libc.stdio as s
cimport pyverbs.libibverbs as v


cdef extern from 'infiniband/hbldv.h':

    cdef struct hbldv_ucontext_attr:
        uint64_t ports_mask
        int core_fd

    cdef struct hbldv_usr_fifo_attr:
        uint32_t port_num
        uint32_t base_sob_addr
        uint32_t num_sobs
        uint32_t usr_fifo_num_hint
        hbldv_usr_fifo_type usr_fifo_type
        uint8_t dir_dup_mask

    cdef struct hbldv_usr_fifo:
        void *ci_cpu_addr
        void *regs_cpu_addr
        uint32_t regs_offset
        uint32_t usr_fifo_num
        uint32_t size
        uint32_t bp_thresh

    cdef struct hbldv_query_cq_attr:
        v.ibv_cq *ibvcq
        void *mem_cpu_addr
        void *pi_cpu_addr
        void *regs_cpu_addr
        uint32_t cq_size
        uint32_t cq_num
        uint32_t regs_offset
        hbldv_cq_type cq_type

    cdef struct hbldv_cq_attr:
        uint8_t port_num
        hbldv_cq_type cq_type

    cdef struct hbldv_wq_array_attr:
        uint32_t max_num_of_wqs
        uint32_t max_num_of_wqes_in_wq
        hbldv_mem_id mem_id
        hbldv_swq_granularity swq_granularity

    cdef struct hbldv_port_ex_attr:
        hbldv_wq_array_attr *wq_arr_attr
        uint64_t caps
        uint8_t *qp_wq_bp_offs
        uint8_t *atomic_fna_fifo_offs
        uint32_t port_num
        uint8_t atomic_fna_mask_size

    cdef struct hbldv_query_port_attr:
        uint32_t max_num_of_qps
        uint32_t num_allocated_qps
        uint32_t max_allocated_qp_num
        uint32_t max_cq_size
        uint32_t speed
        uint32_t reserved0
        uint32_t reserved1
        uint32_t reserved2
        uint32_t reserved3
        uint32_t reserved4
        uint8_t advanced
        uint8_t max_num_of_cqs
        uint8_t max_num_of_usr_fifos
        uint8_t max_num_of_encaps
        uint8_t nic_macro_idx
        uint8_t nic_phys_port_idx

    cdef struct hbldv_qp_attr:
        uint64_t caps
        uint32_t local_key
        uint32_t remote_key
        uint32_t congestion_wnd
        uint32_t reserved0
        uint32_t dest_wq_size
        hbldv_qp_wq_types wq_type
        hbldv_swq_granularity wq_granularity
        uint8_t priority
        uint8_t reserved1
        uint8_t reserved2
        uint8_t encap_num
        uint8_t reserved3

    cdef struct hbldv_query_qp_attr:
        uint32_t qp_num
        void *swq_cpu_addr
        void *rwq_cpu_addr

    cdef struct hbldv_encap:
        uint32_t encap_num

    cdef union l3_l4_data:
        uint16_t udp_dst_port
        uint16_t ip_proto

    cdef struct hbldv_encap_attr:
        uint64_t tnl_hdr_ptr
        uint32_t tnl_hdr_size
        uint32_t ipv4_addr
        l3_l4_data l3_l4_data
        uint32_t port_num
        uint8_t encap_type

    cdef struct hbldv_device_attr:
        uint64_t caps
        uint64_t ports_mask

    bool hbldv_is_supported(v.ibv_device *device)
    v.ibv_context *hbldv_open_device(v.ibv_device *device,
                                     hbldv_ucontext_attr *attr)
    hbldv_usr_fifo *hbldv_create_usr_fifo(v.ibv_context *context,
                                          hbldv_usr_fifo_attr *attr);
    void hbldv_destroy_usr_fifo(hbldv_usr_fifo *usr_fifo);
    v.ibv_cq *hbldv_create_cq(v.ibv_context *context, int cqes, v.ibv_comp_channel *channel,
                              int comp_vector, hbldv_cq_attr *cq_attr)
    int hbldv_query_cq(v.ibv_cq *ibvcq, hbldv_query_cq_attr *cq_attr);
    int hbldv_set_port_ex(v.ibv_context *context, hbldv_port_ex_attr *attr);
    int hbldv_query_port(v.ibv_context *context, uint32_t port_num,
                         hbldv_query_port_attr *hbl_attr);
    int hbldv_modify_qp(v.ibv_qp *ibvqp, v.ibv_qp_attr *attr,
                        int attr_mask, hbldv_qp_attr *qp_attr);
    int hbldv_query_qp(v.ibv_qp *ibvqp, hbldv_query_qp_attr *qp_attr);
    hbldv_encap *hbldv_create_encap(v.ibv_context *context, hbldv_encap_attr *encap_attr)
    int hbldv_destroy_encap(hbldv_encap *hbl_encap)
    int hbldv_query_device(v.ibv_context *context, hbldv_device_attr *attr)
