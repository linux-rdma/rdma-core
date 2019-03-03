# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

include 'libibverbs_enums.pxd'
from libc.stdint cimport uint8_t, uint32_t, uint64_t

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

    cdef struct ibv_mr:
        ibv_context     *context
        ibv_pd          *pd
        void            *addr
        size_t          length
        unsigned int    handle
        unsigned int    lkey
        unsigned int    rkey

    cdef struct ibv_query_device_ex_input:
        unsigned int    comp_mask

    cdef struct per_transport_caps:
        uint32_t rc_odp_caps
        uint32_t uc_odp_caps
        uint32_t ud_odp_caps

    cdef struct ibv_odp_caps:
        uint64_t general_caps
        per_transport_caps per_transport_caps

    cdef struct ibv_tso_caps:
        unsigned int    max_tso
        unsigned int    supported_qpts

    cdef struct ibv_rss_caps:
        unsigned int    supported_qpts
        unsigned int    max_rwq_indirection_tables
        unsigned int    max_rwq_indirection_table_size
        unsigned long   rx_hash_fields_mask
        unsigned int    rx_hash_function

    cdef struct ibv_packet_pacing_caps:
        unsigned int    qp_rate_limit_min
        unsigned int    qp_rate_limit_max
        unsigned int    supported_qpts

    cdef struct ibv_tm_caps:
        unsigned int    max_rndv_hdr_size
        unsigned int    max_num_tags
        unsigned int    flags
        unsigned int    max_ops
        unsigned int    max_sge

    cdef struct ibv_cq_moderation_caps:
        unsigned int    max_cq_count
        unsigned int    max_cq_period

    cdef struct ibv_device_attr_ex:
        ibv_device_attr         orig_attr
        unsigned int            comp_mask
        ibv_odp_caps            odp_caps
        unsigned long           completion_timestamp_mask
        unsigned long           hca_core_clock
        unsigned long           device_cap_flags_ex
        ibv_tso_caps            tso_caps
        ibv_rss_caps            rss_caps
        unsigned int            max_wq_type_rq
        ibv_packet_pacing_caps  packet_pacing_caps
        unsigned int            raw_packet_caps
        ibv_tm_caps             tm_caps
        ibv_cq_moderation_caps  cq_mod_caps
        unsigned long           max_dm_size

    cdef struct ibv_mw:
        ibv_context     *context
        ibv_pd          *pd
        unsigned int    rkey
        unsigned int    handle
        ibv_mw_type     mw_type

    cdef struct ibv_alloc_dm_attr:
        size_t          length
        unsigned int    log_align_req
        unsigned int    comp_mask

    cdef struct ibv_dm:
        ibv_context     *context
        unsigned int    comp_mask

    cdef struct ibv_port_attr:
        ibv_port_state     state
        ibv_mtu            max_mtu
        ibv_mtu            active_mtu
        int                     gid_tbl_len
        unsigned int            port_cap_flags
        unsigned int            max_msg_sz
        unsigned int            bad_pkey_cntr
        unsigned int            qkey_viol_cntr
        unsigned short          pkey_tbl_len
        unsigned short          lid
        unsigned short          sm_lid
        unsigned char           lmc
        unsigned char           max_vl_num
        unsigned char           sm_sl
        unsigned char           subnet_timeout
        unsigned char           init_type_reply
        unsigned char           active_width
        unsigned char           active_speed
        unsigned char           phys_state
        unsigned char           link_layer
        unsigned char           flags
        unsigned short          port_cap_flags2

    ibv_device **ibv_get_device_list(int *n)
    void ibv_free_device_list(ibv_device **list)
    ibv_context *ibv_open_device(ibv_device *device)
    int ibv_close_device(ibv_context *context)
    int ibv_query_device(ibv_context *context, ibv_device_attr *device_attr)
    int ibv_query_device_ex(ibv_context *context,
                            ibv_query_device_ex_input *input,
                            ibv_device_attr_ex *attr)
    unsigned long ibv_get_device_guid(ibv_device *device)
    int ibv_query_gid(ibv_context *context, unsigned int port_num,
                      int index, ibv_gid *gid)
    ibv_pd *ibv_alloc_pd(ibv_context *context)
    int ibv_dealloc_pd(ibv_pd *pd)
    ibv_mr *ibv_reg_mr(ibv_pd *pd, void *addr, size_t length, int access)
    int ibv_dereg_mr(ibv_mr *mr)
    ibv_mw *ibv_alloc_mw(ibv_pd *pd, ibv_mw_type type)
    int ibv_dealloc_mw(ibv_mw *mw)
    ibv_dm *ibv_alloc_dm(ibv_context *context, ibv_alloc_dm_attr *attr)
    int ibv_free_dm(ibv_dm *dm)
    ibv_mr *ibv_reg_dm_mr(ibv_pd *pd, ibv_dm *dm, unsigned long dm_offset,
                          size_t length, unsigned int access)
    int ibv_memcpy_to_dm(ibv_dm *dm, unsigned long dm_offset, void *host_addr,
                         size_t length)
    int ibv_memcpy_from_dm(void *host_addr,  ibv_dm *dm, unsigned long dm_offset,
                           size_t length)
    int ibv_query_port(ibv_context *context, uint8_t port_num,
                       ibv_port_attr *port_attr)
