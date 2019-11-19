# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved. See COPYING file

include 'libibverbs_enums.pxd'
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t

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
        int num_comp_vectors
        int cmd_fd

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

    cdef struct ibv_pci_atomic_caps:
        uint16_t fetch_add
        uint16_t swap
        uint16_t compare_swap

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
        ibv_pci_atomic_caps     pci_atomic_caps
        uint32_t                xrc_odp_caps

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

    cdef struct ibv_comp_channel:
        ibv_context     *context
        unsigned int    fd
        unsigned int    refcnt

    cdef struct ibv_cq:
        ibv_context         *context
        ibv_comp_channel    *channel
        void                *cq_context
        int                 handle
        int                 cqe

    cdef struct ibv_wc:
        unsigned long   wr_id
        ibv_wc_status   status
        ibv_wc_opcode   opcode
        unsigned int    vendor_err
        unsigned int    byte_len
        unsigned int    qp_num
        unsigned int    imm_data
        unsigned int    src_qp
        int             wc_flags
        unsigned int    pkey_index
        unsigned int    slid
        unsigned int    sl
        unsigned int    dlid_path_bits

    cdef struct ibv_cq_init_attr_ex:
        unsigned int        cqe
        void                *cq_context
        ibv_comp_channel    *channel
        unsigned int        comp_vector
        unsigned long       wc_flags
        unsigned int        comp_mask
        unsigned int        flags

    cdef struct ibv_cq_ex:
        ibv_context         *context
        ibv_comp_channel    *channel
        void                *cq_context
        unsigned int        handle
        int                 cqe
        unsigned int        comp_events_completed
        unsigned int        async_events_completed
        unsigned int        comp_mask
        ibv_wc_status       status
        unsigned long       wr_id

    cdef struct ibv_poll_cq_attr:
        unsigned int    comp_mask

    cdef struct ibv_wc_tm_info:
        unsigned long   tag
        unsigned int    priv

    cdef struct ibv_grh:
        unsigned int    version_tclass_flow
        unsigned short    paylen
        unsigned char    next_hdr
        unsigned char    hop_limit
        ibv_gid         sgid
        ibv_gid         dgid

    cdef struct ibv_global_route:
        ibv_gid         dgid
        unsigned int    flow_label
        unsigned char    sgid_index
        unsigned char    hop_limit
        unsigned char    traffic_class

    cdef struct ibv_ah_attr:
        ibv_global_route    grh
        unsigned short        dlid
        unsigned char        sl
        unsigned char        src_path_bits
        unsigned char        static_rate
        unsigned char        is_global
        unsigned char        port_num

    cdef struct ibv_ah:
        ibv_context         *context
        ibv_pd              *pd
        unsigned int        handle

    cdef struct ibv_sge:
        unsigned long   addr
        unsigned int    length
        unsigned int    lkey

    cdef struct ibv_recv_wr:
        unsigned long   wr_id
        ibv_recv_wr     *next
        ibv_sge         *sg_list
        int             num_sge

    cdef struct rdma:
        unsigned long   remote_addr
        unsigned int    rkey

    cdef struct atomic:
        unsigned long   remote_addr
        unsigned long   compare_add
        unsigned long   swap
        unsigned int    rkey

    cdef struct ud:
        ibv_ah          *ah
        unsigned int    remote_qpn
        unsigned int    remote_qkey

    cdef union wr:
        rdma            rdma
        atomic          atomic
        ud              ud

    cdef struct ibv_mw_bind_info:
        ibv_mr          *mr
        unsigned long   addr
        unsigned long   length
        unsigned int    mw_access_flags

    cdef struct bind_mw:
        ibv_mw              *mw
        unsigned int        rkey
        ibv_mw_bind_info    bind_info

    cdef struct tso:
        void            *hdr
        unsigned short  hdr_sz
        unsigned short  mss

    cdef union unnamed:
        bind_mw         bind_mw
        tso             tso

    cdef struct xrc:
        unsigned int    remote_srqn

    cdef union qp_type:
        xrc             xrc

    cdef struct ibv_send_wr:
        unsigned long   wr_id
        ibv_send_wr     *next
        ibv_sge         *sg_list
        int             num_sge
        ibv_wr_opcode   opcode
        unsigned int    send_flags
        wr              wr
        qp_type         qp_type
        unnamed         unnamed

    cdef struct ibv_qp_cap:
        unsigned int    max_send_wr
        unsigned int    max_recv_wr
        unsigned int    max_send_sge
        unsigned int    max_recv_sge
        unsigned int    max_inline_data

    cdef struct ibv_qp_init_attr:
        void            *qp_context
        ibv_cq          *send_cq
        ibv_cq          *recv_cq
        ibv_srq         *srq
        ibv_qp_cap      cap
        ibv_qp_type     qp_type
        int             sq_sig_all

    cdef struct ibv_xrcd_init_attr:
        uint32_t comp_mask
        int      fd
        int      oflags

    cdef struct ibv_xrcd:
        pass

    cdef struct ibv_srq_attr:
        unsigned int    max_wr
        unsigned int    max_sge
        unsigned int    srq_limit

    cdef struct ibv_srq_init_attr:
        void            *srq_context
        ibv_srq_attr    attr

    cdef struct ibv_srq_init_attr_ex:
        void            *srq_context
        ibv_srq_attr    attr
        unsigned int    comp_mask
        ibv_srq_type    srq_type
        ibv_pd          *pd
        ibv_xrcd        *xrcd
        ibv_cq          *cq
        ibv_tm_caps      tm_cap

    cdef struct ibv_srq:
        ibv_context     *context
        void            *srq_context
        ibv_pd          *pd
        unsigned int    handle
        unsigned int    events_completed

    cdef struct ibv_rwq_ind_table:
        pass

    cdef struct ibv_rx_hash_conf:
        pass

    cdef struct ibv_qp_init_attr_ex:
        void                *qp_context
        ibv_cq              *send_cq
        ibv_cq              *recv_cq
        ibv_srq             *srq
        ibv_qp_cap          cap
        ibv_qp_type         qp_type
        int                 sq_sig_all
        unsigned int        comp_mask
        ibv_pd              *pd
        ibv_xrcd            *xrcd
        unsigned int        create_flags
        unsigned short      max_tso_header
        ibv_rwq_ind_table   *rwq_ind_tbl
        ibv_rx_hash_conf    rx_hash_conf
        unsigned int        source_qpn
        unsigned long       send_ops_flags

    cdef struct ibv_qp_attr:
        ibv_qp_state    qp_state
        ibv_qp_state    cur_qp_state
        ibv_mtu         path_mtu
        ibv_mig_state   path_mig_state
        unsigned int    qkey
        unsigned int    rq_psn
        unsigned int    sq_psn
        unsigned int    dest_qp_num
        unsigned int    qp_access_flags
        ibv_qp_cap      cap
        ibv_ah_attr     ah_attr
        ibv_ah_attr     alt_ah_attr
        unsigned short  pkey_index
        unsigned short  alt_pkey_index
        unsigned char   en_sqd_async_notify
        unsigned char   sq_draining
        unsigned char   max_rd_atomic
        unsigned char   max_dest_rd_atomic
        unsigned char   min_rnr_timer
        unsigned char   port_num
        unsigned char   timeout
        unsigned char   retry_cnt
        unsigned char   rnr_retry
        unsigned char   alt_port_num
        unsigned char   alt_timeout
        unsigned int    rate_limit

    cdef struct ibv_srq:
        ibv_context     *context
        void            *srq_context
        ibv_pd          *pd
        unsigned int    handle
        unsigned int    events_completed

    cdef struct ibv_qp:
        ibv_context     *context;
        void            *qp_context;
        ibv_pd          *pd;
        ibv_cq          *send_cq;
        ibv_cq          *recv_cq;
        ibv_srq         *srq;
        unsigned int    handle;
        unsigned int    qp_num;
        ibv_qp_state    state;
        ibv_qp_type     qp_type;
        unsigned int    events_completed;

    cdef struct ibv_parent_domain_init_attr:
        ibv_pd          *pd;
        uint32_t        comp_mask;
        void            *(*alloc)(ibv_pd *pd, void *pd_context, size_t size,
                                  size_t alignment, uint64_t resource_type);
        void            (*free)(ibv_pd *pd, void *pd_context, void *ptr,
                                uint64_t resource_type);
        void            *pd_context;

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
    ibv_comp_channel *ibv_create_comp_channel(ibv_context *context)
    int ibv_destroy_comp_channel(ibv_comp_channel *channel)
    int ibv_get_cq_event(ibv_comp_channel *channel, ibv_cq **cq,
                         void **cq_context)
    int ibv_req_notify_cq(ibv_cq *cq, int solicited_only)
    void ibv_ack_cq_events(ibv_cq *cq, int nevents)
    ibv_cq *ibv_create_cq(ibv_context *context, int cqe, void *cq_context,
                          ibv_comp_channel *channel, int comp_vector)
    int ibv_destroy_cq(ibv_cq *cq)
    int ibv_poll_cq(ibv_cq *cq, int num_entries, ibv_wc *wc)
    ibv_cq_ex *ibv_create_cq_ex(ibv_context *context,
                                ibv_cq_init_attr_ex *cq_attr)
    ibv_cq *ibv_cq_ex_to_cq(ibv_cq_ex *cq)
    int ibv_start_poll(ibv_cq_ex *cq, ibv_poll_cq_attr *attr)
    int ibv_next_poll(ibv_cq_ex *cq)
    void ibv_end_poll(ibv_cq_ex *cq)
    ibv_wc_opcode ibv_wc_read_opcode(ibv_cq_ex *cq)
    unsigned int ibv_wc_read_vendor_err(ibv_cq_ex *cq)
    unsigned int ibv_wc_read_byte_len(ibv_cq_ex *cq)
    unsigned int ibv_wc_read_imm_data(ibv_cq_ex *cq)
    unsigned int ibv_wc_read_invalidated_rkey(ibv_cq_ex *cq)
    unsigned int ibv_wc_read_qp_num(ibv_cq_ex *cq)
    unsigned int ibv_wc_read_src_qp(ibv_cq_ex *cq)
    unsigned int ibv_wc_read_wc_flags(ibv_cq_ex *cq)
    unsigned int ibv_wc_read_slid(ibv_cq_ex *cq)
    unsigned char ibv_wc_read_sl(ibv_cq_ex *cq)
    unsigned char ibv_wc_read_dlid_path_bits(ibv_cq_ex *cq)
    unsigned long ibv_wc_read_completion_ts(ibv_cq_ex *cq)
    unsigned short ibv_wc_read_cvlan(ibv_cq_ex *cq)
    unsigned int ibv_wc_read_flow_tag(ibv_cq_ex *cq)
    void ibv_wc_read_tm_info(ibv_cq_ex *cq, ibv_wc_tm_info *tm_info)
    unsigned long ibv_wc_read_completion_wallclock_ns(ibv_cq_ex *cq)
    ibv_ah *ibv_create_ah(ibv_pd *pd, ibv_ah_attr *attr)
    int ibv_init_ah_from_wc(ibv_context *context, uint8_t port_num,
                            ibv_wc *wc, ibv_grh *grh, ibv_ah_attr *ah_attr)
    ibv_ah *ibv_create_ah_from_wc(ibv_pd *pd, ibv_wc *wc, ibv_grh *grh,
                                  uint8_t port_num)
    int ibv_destroy_ah(ibv_ah *ah)
    ibv_qp *ibv_create_qp(ibv_pd *pd, ibv_qp_init_attr *qp_init_attr)
    ibv_qp *ibv_create_qp_ex(ibv_context *context,
                             ibv_qp_init_attr_ex *qp_init_attr_ex)
    int ibv_modify_qp(ibv_qp *qp, ibv_qp_attr *qp_attr, int comp_mask)
    int ibv_query_qp(ibv_qp *qp, ibv_qp_attr *attr, int attr_mask,
                     ibv_qp_init_attr *init_attr)
    int ibv_destroy_qp(ibv_qp *qp)
    int ibv_post_recv(ibv_qp *qp, ibv_recv_wr *wr, ibv_recv_wr **bad_wr)
    int ibv_post_send(ibv_qp *qp, ibv_send_wr *wr, ibv_send_wr **bad_wr)
    ibv_xrcd *ibv_open_xrcd(ibv_context *context,
                            ibv_xrcd_init_attr *xrcd_init_attr)
    int ibv_close_xrcd(ibv_xrcd *xrcd)
    ibv_srq *ibv_create_srq(ibv_pd *pd, ibv_srq_init_attr *srq_init_attr)
    ibv_srq *ibv_create_srq_ex(ibv_context *context,
                               ibv_srq_init_attr_ex *srq_init_attr)
    int ibv_modify_srq(ibv_srq *srq, ibv_srq_attr *srq_attr, int srq_attr_mask)
    int ibv_query_srq(ibv_srq *srq, ibv_srq_attr *srq_attr)
    int ibv_get_srq_num(ibv_srq *srq, unsigned int *srq_num)
    int ibv_destroy_srq(ibv_srq *srq)
    int ibv_post_srq_recv(ibv_srq *srq, ibv_recv_wr *recv_wr,
                          ibv_recv_wr **bad_recv_wr)
    ibv_pd *ibv_alloc_parent_domain(ibv_context *context,
                                    ibv_parent_domain_init_attr *attr)
