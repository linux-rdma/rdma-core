# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

include 'libibverbs_enums.pxd'
from libc.stdint cimport uint8_t, uint64_t

cdef extern from 'infiniband/verbs.h':

    cdef struct anon:
        unsigned long subnet_prefix
        unsigned long interface_id

    cdef union ibv_gid:
        anon _global "global"
        uint8_t raw[16]

    cdef struct ibv_device:
        char *name
        int node_type
        int transport_type

    cdef struct ibv_context:
        ibv_device *device

    cdef struct ibv_device_attr:
        char            *fw_ver
        unsigned long   node_guid
        unsigned long   sys_image_guid
        unsigned long   max_mr_size
        unsigned long   page_size_cap
        unsigned int    vendor_id
        unsigned int    vendor_part_id
        unsigned int    hw_ver
        unsigned int    max_qp
        unsigned int    max_qp_wr
        unsigned int    device_cap_flags
        unsigned int    max_sge
        unsigned int    max_sge_rd
        unsigned int    max_cq
        unsigned int    max_cqe
        unsigned int    max_mr
        unsigned int    max_pd
        unsigned int    max_qp_rd_atom
        unsigned int    max_ee_rd_atom
        unsigned int    max_res_rd_atom
        unsigned int    max_qp_init_rd_atom
        unsigned int    max_ee_init_rd_atom
        ibv_atomic_cap  atomic_cap
        unsigned int    max_ee
        unsigned int    max_rdd
        unsigned int    max_mw
        unsigned int    max_raw_ipv6_qp
        unsigned int    max_raw_ethy_qp
        unsigned int    max_mcast_grp
        unsigned int    max_mcast_qp_attach
        unsigned int    max_total_mcast_qp_attach
        unsigned int    max_ah
        unsigned int    max_fmr
        unsigned int    max_map_per_fmr
        unsigned int    max_srq
        unsigned int    max_srq_wr
        unsigned int    max_srq_sge
        unsigned int    max_pkeys
        unsigned int    local_ca_ack_delay
        unsigned int    phys_port_cnt

    struct ibv_pd:
        ibv_context     *context
        unsigned int    handle

    ibv_device **ibv_get_device_list(int *n)
    void ibv_free_device_list(ibv_device **list)
    ibv_context *ibv_open_device(ibv_device *device)
    int ibv_close_device(ibv_context *context)
    int ibv_query_device(ibv_context *context, ibv_device_attr *device_attr)
    unsigned long ibv_get_device_guid(ibv_device *device)
    int ibv_query_gid(ibv_context *context, unsigned int port_num,
                      int index, ibv_gid *gid)
    ibv_pd *ibv_alloc_pd(ibv_context *context)
    int ibv_dealloc_pd(ibv_pd *pd)
