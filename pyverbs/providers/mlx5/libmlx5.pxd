# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

include 'mlx5dv_enums.pxd'

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, uintptr_t
from posix.types cimport off_t
from libcpp cimport bool
cimport libc.stdio as s

cimport pyverbs.libibverbs as v


cdef extern from 'infiniband/mlx5dv.h':

    cdef struct mlx5dv_context_attr:
        unsigned int    flags
        unsigned long   comp_mask

    cdef struct mlx5dv_cqe_comp_caps:
        unsigned int    max_num
        unsigned int    supported_format

    cdef struct mlx5dv_sw_parsing_caps:
        unsigned int    sw_parsing_offloads
        unsigned int    supported_qpts

    cdef struct mlx5dv_striding_rq_caps:
        unsigned int    min_single_stride_log_num_of_bytes
        unsigned int    max_single_stride_log_num_of_bytes
        unsigned int    min_single_wqe_log_num_of_strides
        unsigned int    max_single_wqe_log_num_of_strides
        unsigned int    supported_qpts

    cdef struct mlx5dv_dci_streams_caps:
        uint8_t    max_log_num_concurent
        uint8_t    max_log_num_errored

    cdef struct mlx5dv_crypto_caps:
        uint16_t failed_selftests
        uint8_t crypto_engines
        uint8_t wrapped_import_method
        uint8_t log_max_num_deks
        uint32_t flags

    cdef struct mlx5dv_context:
        unsigned char           version
        unsigned long           flags
        unsigned long           comp_mask
        mlx5dv_cqe_comp_caps    cqe_comp_caps
        mlx5dv_sw_parsing_caps  sw_parsing_caps
        mlx5dv_striding_rq_caps striding_rq_caps
        mlx5dv_dci_streams_caps dci_streams_caps
        unsigned int            tunnel_offloads_caps
        unsigned int            max_dynamic_bfregs
        unsigned long           max_clock_info_update_nsec
        unsigned int            flow_action_flags
        unsigned int            dc_odp_caps
        uint8_t                 num_lag_ports
        mlx5dv_crypto_caps      crypto_caps
        size_t                  max_wr_memcpy_length

    cdef struct mlx5dv_dci_streams:
        uint8_t       log_num_concurent
        uint8_t       log_num_errored

    cdef struct mlx5dv_dc_init_attr:
        mlx5dv_dc_type      dc_type
        unsigned long       dct_access_key
        mlx5dv_dci_streams  dci_streams

    cdef struct mlx5dv_qp_init_attr:
        unsigned long       comp_mask
        unsigned int        create_flags
        mlx5dv_dc_init_attr dc_init_attr
        unsigned long       send_ops_flags

    cdef struct mlx5dv_cq_init_attr:
        unsigned long   comp_mask
        unsigned char   cqe_comp_res_format
        unsigned int    flags
        unsigned short  cqe_size

    cdef struct mlx5dv_var:
        uint32_t    page_id
        uint32_t    length
        long        mmap_off
        uint64_t    comp_mask

    cdef struct mlx5dv_pp:
        uint16_t index

    cdef struct mlx5dv_devx_uar:
        void        *reg_addr;
        void        *base_addr;
        uint32_t    page_id;
        long        mmap_off;
        uint64_t    comp_mask;

    cdef struct mlx5dv_qp_ex:
        uint64_t comp_mask

    cdef struct mlx5dv_sched_node

    cdef struct mlx5dv_sched_leaf

    cdef struct mlx5dv_sched_attr:
        mlx5dv_sched_node *parent;
        uint32_t flags;
        uint32_t bw_share;
        uint32_t max_avg_bw;
        uint64_t comp_mask;

    cdef struct mlx5dv_reg:
        uint32_t value;
        uint32_t mask;

    cdef struct mlx5dv_port:
        uint64_t flags
        uint16_t vport
        uint16_t vport_vhca_id
        uint16_t esw_owner_vhca_id
        uint64_t vport_steering_icm_rx
        uint64_t vport_steering_icm_tx
        mlx5dv_reg reg_c0

    cdef struct mlx5dv_flow_match_parameters:
        size_t   match_sz;
        uint64_t *match_buf;

    cdef struct mlx5dv_flow_matcher_attr:
        v.ibv_flow_attr_type         type;
        uint32_t                     flags;
        uint16_t                     priority;
        uint8_t                      match_criteria_enable;
        mlx5dv_flow_match_parameters *match_mask;
        uint64_t                     comp_mask;
        mlx5_ib_uapi_flow_table_type ft_type;

    cdef struct mlx5dv_flow_matcher

    cdef struct mlx5dv_devx_obj

    cdef struct mlx5dv_flow_action_attr:
        mlx5dv_flow_action_type type
        v.ibv_qp                *qp
        v.ibv_flow_action       *action
        unsigned int            tag_value
        mlx5dv_devx_obj         *obj

    cdef struct mlx5dv_dr_domain

    cdef struct mlx5dv_dr_table

    cdef struct mlx5dv_dr_matcher

    cdef struct mlx5dv_dr_matcher_layout:
        uint32_t flags
        uint32_t log_num_of_rules_hint

    cdef struct mlx5dv_dr_action

    cdef struct mlx5dv_dr_rule

    cdef struct mlx5dv_dr_action_dest_reformat:
        mlx5dv_dr_action *reformat
        mlx5dv_dr_action *dest

    cdef struct mlx5dv_dr_action_dest_attr:
        mlx5dv_dr_action_dest_type type
        mlx5dv_dr_action *dest
        mlx5dv_dr_action_dest_reformat *dest_reformat

    cdef struct mlx5dv_clock_info:
        pass

    cdef struct mlx5dv_mkey_init_attr:
        v.ibv_pd *pd
        uint32_t create_flags
        uint16_t max_entries

    cdef struct mlx5dv_mkey:
        uint32_t lkey
        uint32_t rkey

    cdef struct mlx5dv_mr_interleaved:
        uint64_t addr
        uint32_t bytes_count
        uint32_t bytes_skip
        uint32_t lkey

    cdef struct mlx5dv_mkey_conf_attr:
        uint32_t conf_flags
        uint64_t comp_mask

    cdef struct mlx5dv_sig_crc:
        mlx5dv_sig_crc_type type
        uint64_t seed

    cdef struct mlx5dv_sig_t10dif:
        mlx5dv_sig_t10dif_bg_type bg_type
        uint16_t bg
        uint16_t app_tag
        uint32_t ref_tag
        uint16_t flags

    cdef union sig:
        mlx5dv_sig_t10dif *dif
        mlx5dv_sig_crc *crc

    cdef struct mlx5dv_sig_block_domain:
        mlx5dv_sig_type sig_type
        sig sig
        mlx5dv_block_size block_size
        uint64_t comp_mask

    cdef struct mlx5dv_sig_block_attr:
        mlx5dv_sig_block_domain *mem
        mlx5dv_sig_block_domain *wire
        uint32_t flags
        uint8_t check_mask
        uint8_t copy_mask
        uint64_t comp_mask

    cdef struct mlx5dv_sig_err:
        uint64_t actual_value
        uint64_t expected_value
        uint64_t offset

    cdef union err:
        mlx5dv_sig_err sig

    cdef struct mlx5dv_mkey_err:
        mlx5dv_mkey_err_type err_type
        err err

    cdef struct mlx5_wqe_data_seg:
        uint32_t    byte_count
        uint32_t    lkey
        uint64_t    addr

    cdef struct mlx5_wqe_ctrl_seg:
        uint32_t    opmod_idx_opcode
        uint32_t    qpn_ds
        uint8_t     signature
        uint8_t     fm_ce_se
        uint32_t    imm

    cdef struct mlx5dv_devx_umem:
        uint32_t umem_id;

    cdef struct mlx5dv_devx_umem_in:
        void        *addr
        size_t      size
        uint32_t    access
        uint64_t    pgsz_bitmap
        uint64_t    comp_mask

    cdef struct mlx5dv_vfio_context_attr:
        const char  *pci_name
        uint32_t    flags
        uint64_t    comp_mask

    cdef struct mlx5dv_pd:
        uint32_t    pdn
        uint64_t    comp_mask

    cdef struct mlx5dv_cq:
        void        *buf
        uint32_t    *dbrec
        uint32_t    cqe_cnt
        uint32_t    cqe_size
        void        *cq_uar
        uint32_t    cqn
        uint64_t    comp_mask

    cdef struct mlx5dv_qp:
        uint64_t    comp_mask
        off_t       uar_mmap_offset
        uint32_t    tirn
        uint32_t    tisn
        uint32_t    rqn
        uint32_t    sqn

    cdef struct mlx5dv_srq:
        uint32_t    stride
        uint32_t    head
        uint32_t    tail
        uint64_t    comp_mask
        uint32_t    srqn

    cdef struct pd:
        v.ibv_pd    *in_ "in"
        mlx5dv_pd   *out

    cdef struct cq:
        v.ibv_cq    *in_ "in"
        mlx5dv_cq   *out

    cdef struct qp:
        v.ibv_qp    *in_ "in"
        mlx5dv_qp   *out

    cdef struct srq:
        v.ibv_srq   *in_ "in"
        mlx5dv_srq  *out

    cdef struct mlx5dv_obj:
        pd  pd
        cq  cq
        qp  qp
        srq srq

    cdef struct mlx5_cqe64:
        uint16_t    wqe_id
        uint32_t    imm_inval_pkey
        uint32_t    byte_cnt
        uint64_t    timestamp
        uint16_t    wqe_counter
        uint8_t     signature
        uint8_t     op_own


    void mlx5dv_set_ctrl_seg(mlx5_wqe_ctrl_seg *seg, uint16_t pi, uint8_t opcode,
                             uint8_t opmod, uint32_t qp_num, uint8_t fm_ce_se,
                             uint8_t ds, uint8_t signature, uint32_t imm)
    void mlx5dv_set_data_seg(mlx5_wqe_data_seg *seg, uint32_t length,
                             uint32_t lkey, uintptr_t address)
    uint8_t mlx5dv_get_cqe_owner(mlx5_cqe64 *cqe)
    void mlx5dv_set_cqe_owner(mlx5_cqe64 *cqe, uint8_t val)
    uint8_t mlx5dv_get_cqe_se(mlx5_cqe64 *cqe)
    uint8_t mlx5dv_get_cqe_format(mlx5_cqe64 *cqe)
    uint8_t mlx5dv_get_cqe_opcode(mlx5_cqe64 *cqe)

    cdef struct mlx5dv_dek:
        pass

    cdef struct mlx5dv_crypto_login_attr:
        uint32_t credential_id
        uint32_t import_kek_id
        char *credential
        uint64_t comp_mask

    cdef struct mlx5dv_crypto_attr:
        mlx5dv_crypto_standard crypto_standard
        bool encrypt_on_tx
        mlx5dv_signature_crypto_order signature_crypto_order
        mlx5dv_block_size data_unit_size
        char *initial_tweak
        mlx5dv_dek *dek
        char *keytag
        uint64_t comp_mask

    cdef struct mlx5dv_dek_init_attr:
        mlx5dv_crypto_key_size key_size
        bool has_keytag
        mlx5dv_crypto_key_purpose key_purpose
        v.ibv_pd *pd
        char *opaque
        char *key
        uint64_t comp_mask

    cdef struct mlx5dv_dek_attr:
        mlx5dv_dek_state state
        char *opaque
        uint64_t comp_mask

    bool mlx5dv_is_supported(v.ibv_device *device)
    v.ibv_context* mlx5dv_open_device(v.ibv_device *device,
                                      mlx5dv_context_attr *attr)
    int mlx5dv_query_device(v.ibv_context *ctx, mlx5dv_context *attrs_out)

    v.ibv_qp *mlx5dv_create_qp(v.ibv_context *context,
                               v.ibv_qp_init_attr_ex *qp_attr,
                               mlx5dv_qp_init_attr *mlx5_qp_attr)
    int mlx5dv_query_qp_lag_port(v.ibv_qp *qp, uint8_t *port_num,
                                 uint8_t *active_port_num)
    int mlx5dv_modify_qp_lag_port(v.ibv_qp *qp, uint8_t port_num)
    int mlx5dv_modify_qp_udp_sport(v.ibv_qp *qp, uint16_t udp_sport)
    int mlx5dv_dci_stream_id_reset(v.ibv_qp *qp, uint16_t stream_id)
    v.ibv_cq_ex *mlx5dv_create_cq(v.ibv_context *context,
                                  v.ibv_cq_init_attr_ex *cq_attr,
                                  mlx5dv_cq_init_attr *mlx5_cq_attr)
    void mlx5dv_wr_raw_wqe(mlx5dv_qp_ex *mqp_ex, const void *wqe)
    mlx5dv_var *mlx5dv_alloc_var(v.ibv_context *context, uint32_t flags)
    void mlx5dv_free_var(mlx5dv_var *dv_var)
    mlx5dv_pp *mlx5dv_pp_alloc(v.ibv_context *context, size_t pp_context_sz,
                               const void *pp_context, uint32_t flags)
    void mlx5dv_pp_free(mlx5dv_pp *pp)
    void mlx5dv_wr_set_dc_addr(mlx5dv_qp_ex *mqp, v.ibv_ah *ah,
                               uint32_t remote_dctn, uint64_t remote_dc_key)
    void mlx5dv_wr_set_dc_addr_stream(mlx5dv_qp_ex *mqp, v.ibv_ah *ah,
                                      uint32_t remote_dctn, uint64_t remote_dc_key,
                                      uint16_t stream_id)
    void mlx5dv_wr_mr_interleaved(mlx5dv_qp_ex *mqp, mlx5dv_mkey *mkey,
                                  uint32_t access_flags, uint32_t repeat_count,
                                  uint16_t num_interleaved, mlx5dv_mr_interleaved *data)
    void mlx5dv_wr_mr_list(mlx5dv_qp_ex *mqp, mlx5dv_mkey *mkey,
                           uint32_t access_flags, uint16_t num_sge, v.ibv_sge *sge)
    void mlx5dv_wr_memcpy(mlx5dv_qp_ex *mqp, uint32_t dest_lkey, uint64_t dest_addr,
                          uint32_t src_lkey, uint64_t src_addr, uint64_t length)
    mlx5dv_mkey *mlx5dv_create_mkey(mlx5dv_mkey_init_attr *mkey_init_attr)
    int mlx5dv_destroy_mkey(mlx5dv_mkey *mkey)
    mlx5dv_qp_ex *mlx5dv_qp_ex_from_ibv_qp_ex(v.ibv_qp_ex *qp_ex)
    mlx5dv_sched_node *mlx5dv_sched_node_create(v.ibv_context *context,
                                                mlx5dv_sched_attr *sched_attr)
    mlx5dv_sched_leaf *mlx5dv_sched_leaf_create(v.ibv_context *context,
                                                mlx5dv_sched_attr *sched_attr)
    int mlx5dv_sched_node_modify(mlx5dv_sched_node *node,
                                 mlx5dv_sched_attr *sched_attr)
    int mlx5dv_sched_leaf_modify(mlx5dv_sched_leaf *leaf,
                                 mlx5dv_sched_attr *sched_attr)
    int mlx5dv_sched_node_destroy(mlx5dv_sched_node *node)
    int mlx5dv_sched_leaf_destroy(mlx5dv_sched_leaf *leaf)
    int mlx5dv_modify_qp_sched_elem(v.ibv_qp *qp, mlx5dv_sched_leaf *requestor,
                                    mlx5dv_sched_leaf *responder)
    int mlx5dv_reserved_qpn_alloc(v.ibv_context *context, uint32_t *qpn)
    int mlx5dv_reserved_qpn_dealloc(v.ibv_context *context, uint32_t qpn)
    void *mlx5dv_dm_map_op_addr(v.ibv_dm *dm, uint8_t op)
    int mlx5dv_query_port(v.ibv_context *context, uint32_t port_num, mlx5dv_port *port)
    mlx5dv_flow_matcher *mlx5dv_create_flow_matcher(v.ibv_context *context,
                                                    mlx5dv_flow_matcher_attr *matcher_attr)
    int mlx5dv_destroy_flow_matcher(mlx5dv_flow_matcher *matcher)
    v.ibv_flow *mlx5dv_create_flow(mlx5dv_flow_matcher *matcher,
                                   mlx5dv_flow_match_parameters *match_value,
                                   size_t num_actions,
                                   mlx5dv_flow_action_attr actions_attr[])
    v.ibv_flow_action *mlx5dv_create_flow_action_packet_reformat(v.ibv_context *context,
                                                                 size_t data_sz,
                                                                 void *data,
                                                                 unsigned char reformat_type,
                                                                 unsigned char ft_type)

    # Direct rules verbs
    mlx5dv_dr_domain *mlx5dv_dr_domain_create(v.ibv_context *ctx, mlx5dv_dr_domain_type type)
    int mlx5dv_dr_domain_sync(mlx5dv_dr_domain *domain, uint32_t flags)
    int mlx5dv_dump_dr_domain(s.FILE *fout, mlx5dv_dr_domain *domain)
    int mlx5dv_dr_domain_destroy(mlx5dv_dr_domain *dmn)
    mlx5dv_dr_table *mlx5dv_dr_table_create(mlx5dv_dr_domain *dmn, uint32_t level)
    int mlx5dv_dr_table_destroy(mlx5dv_dr_table *tbl)
    mlx5dv_dr_matcher *mlx5dv_dr_matcher_create(mlx5dv_dr_table *table,
                                                uint16_t priority,
                                                uint8_t match_criteria_enable,
                                                mlx5dv_flow_match_parameters *mask)
    int mlx5dv_dr_matcher_set_layout(mlx5dv_dr_matcher *matcher, mlx5dv_dr_matcher_layout *layout)
    int mlx5dv_dr_matcher_destroy(mlx5dv_dr_matcher *matcher)
    mlx5dv_dr_action *mlx5dv_dr_action_create_dest_ibv_qp(v.ibv_qp *ibqp)
    mlx5dv_dr_action *mlx5dv_dr_action_create_tag(uint32_t tag_value)
    mlx5dv_dr_action *mlx5dv_dr_action_create_dest_table(mlx5dv_dr_table *tbl)
    mlx5dv_dr_action *mlx5dv_dr_action_create_pop_vlan()
    mlx5dv_dr_action *mlx5dv_dr_action_create_push_vlan(mlx5dv_dr_domain *dmn,
                                                        uint32_t vlan_hdr)
    mlx5dv_dr_action *mlx5dv_dr_action_create_dest_array(
            mlx5dv_dr_domain *domain, size_t num_dest,
            mlx5dv_dr_action_dest_attr *dests[])
    int mlx5dv_dr_action_destroy(mlx5dv_dr_action *action)
    mlx5dv_dr_rule *mlx5dv_dr_rule_create(mlx5dv_dr_matcher *matcher,
                                          mlx5dv_flow_match_parameters *value,
                                          size_t num_actions,
                                          mlx5dv_dr_action *actions[])
    mlx5dv_dr_action *mlx5dv_dr_action_create_modify_header(mlx5dv_dr_domain *dmn, uint32_t flags,
                                                            size_t actions_sz, uint64_t actions[])
    mlx5dv_dr_action *mlx5dv_dr_action_create_flow_counter(mlx5dv_devx_obj *devx_obj,
                                                           uint32_t offset)
    mlx5dv_dr_action *mlx5dv_dr_action_create_drop()
    mlx5dv_dr_action *mlx5dv_dr_action_create_default_miss()
    mlx5dv_dr_action *mlx5dv_dr_action_create_dest_vport(mlx5dv_dr_domain *dmn,
                                                         uint32_t vport)
    mlx5dv_dr_action *mlx5dv_dr_action_create_dest_ib_port(mlx5dv_dr_domain *dmn,
                                                           uint32_t ib_port)
    int mlx5dv_dr_rule_destroy(mlx5dv_dr_rule *rule)
    void mlx5dv_dr_domain_allow_duplicate_rules(mlx5dv_dr_domain *dmn, bool allow)

    uint64_t mlx5dv_ts_to_ns(mlx5dv_clock_info *clock_info,
                             uint64_t device_timestamp)
    int mlx5dv_get_clock_info(v.ibv_context *ctx_in, mlx5dv_clock_info *clock_info)
    int mlx5dv_map_ah_to_qp(v.ibv_ah *ah, uint32_t qp_num)
    v.ibv_device **mlx5dv_get_vfio_device_list(mlx5dv_vfio_context_attr *attr)
    int mlx5dv_vfio_get_events_fd(v.ibv_context *ibctx)
    int mlx5dv_vfio_process_events(v.ibv_context *context)

    # DevX APIs
    mlx5dv_devx_uar *mlx5dv_devx_alloc_uar(v.ibv_context *context, uint32_t flags)
    void mlx5dv_devx_free_uar(mlx5dv_devx_uar *devx_uar)
    int mlx5dv_devx_general_cmd(v.ibv_context *context, const void *in_,
                                size_t inlen, void *out, size_t outlen)
    mlx5dv_devx_umem *mlx5dv_devx_umem_reg(v.ibv_context *ctx, void *addr,
                                           size_t size, unsigned long access)
    mlx5dv_devx_umem *mlx5dv_devx_umem_reg_ex(v.ibv_context *ctx,
                                              mlx5dv_devx_umem_in *umem_in)
    int mlx5dv_devx_umem_dereg(mlx5dv_devx_umem *umem)
    int mlx5dv_devx_query_eqn(v.ibv_context *context, uint32_t vector, uint32_t *eqn)
    mlx5dv_devx_obj *mlx5dv_devx_obj_create(v.ibv_context *context, const void *_in,
                                            size_t inlen, void *out, size_t outlen)
    int mlx5dv_devx_obj_query(mlx5dv_devx_obj *obj, const void *in_,
                              size_t inlen, void *out, size_t outlen)
    int mlx5dv_devx_obj_modify(mlx5dv_devx_obj *obj, const void *in_,
                               size_t inlen, void *out, size_t outlen)
    int mlx5dv_devx_obj_destroy(mlx5dv_devx_obj *obj)
    int mlx5dv_init_obj(mlx5dv_obj *obj, uint64_t obj_type)

    # Mkey setters
    void mlx5dv_wr_mkey_configure(mlx5dv_qp_ex *mqp, mlx5dv_mkey *mkey,
                                 int num_setters, mlx5dv_mkey_conf_attr *attr)
    void mlx5dv_wr_set_mkey_access_flags(mlx5dv_qp_ex *mqp, uint32_t access_flags)
    void mlx5dv_wr_set_mkey_layout_list(mlx5dv_qp_ex *mqp, uint16_t num_sges, v.ibv_sge *sge)
    void mlx5dv_wr_set_mkey_layout_interleaved(mlx5dv_qp_ex *mqp, uint32_t repeat_count,
                                               uint16_t num_interleaved,
                                               mlx5dv_mr_interleaved *data)
    void mlx5dv_wr_set_mkey_sig_block(mlx5dv_qp_ex *mqp, mlx5dv_sig_block_attr *attr)
    int mlx5dv_mkey_check(mlx5dv_mkey *mkey, mlx5dv_mkey_err *err_info)
    int mlx5dv_qp_cancel_posted_send_wrs(mlx5dv_qp_ex *mqp, uint64_t wr_id)
    void mlx5dv_wr_set_mkey_crypto(mlx5dv_qp_ex *mqp, mlx5dv_crypto_attr *attr)

    # Crypto APIs
    int mlx5dv_crypto_login(v.ibv_context *context, mlx5dv_crypto_login_attr *login_attr)
    int mlx5dv_crypto_login_query_state(v.ibv_context *context, mlx5dv_crypto_login_state *state)
    int mlx5dv_crypto_logout(v.ibv_context *context)
    mlx5dv_dek *mlx5dv_dek_create(v.ibv_context *context, mlx5dv_dek_init_attr *init_attr)
    int mlx5dv_dek_query(mlx5dv_dek *dek, mlx5dv_dek_attr *attr)
    int mlx5dv_dek_destroy(mlx5dv_dek *dek)
