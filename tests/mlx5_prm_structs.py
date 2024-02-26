# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia Inc. All rights reserved. See COPYING file

"""
This module provides scapy based classes that represent the mlx5 PRM structs.
"""
import unittest

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.packet import Packet
    from scapy.fields import BitField, ByteField, IntField, IPField, \
        ShortField, LongField, StrFixedLenField, PacketField, \
        PacketListField, ConditionalField, PadField, FieldListField, MACField, \
        MultipleTypeField
    from scapy.layers.inet6 import IP6Field
except ImportError:
    raise unittest.SkipTest('scapy package is needed in order to run DevX tests')


class DevxOps:
    MLX5_CMD_OP_ALLOC_PD = 0x800
    MLX5_CMD_OP_CREATE_CQ = 0x400
    MLX5_CMD_OP_QUERY_CQ = 0x402
    MLX5_CMD_OP_MODIFY_CQ = 0x403
    MLX5_CMD_OP_CREATE_QP = 0x500
    MLX5_CMD_OP_QUERY_QP = 0x50b
    MLX5_CMD_OP_RST2INIT_QP = 0x502
    MLX5_CMD_OP_INIT2RTR_QP = 0x503
    MLX5_CMD_OP_RTR2RTS_QP = 0x504
    MLX5_CMD_OP_RTS2RTS_QP = 0x505
    MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT = 0x762
    MLX5_CMD_OP_QUERY_HCA_VPORT_GID = 0x764
    MLX5_QPC_ST_RC = 0X0
    MLX5_QPC_PM_STATE_MIGRATED = 0x3
    MLX5_CMD_OP_QUERY_HCA_CAP = 0x100
    MLX5_CMD_OP_QUERY_QOS_CAP = 0xc
    MLX5_CMD_OP_ALLOC_FLOW_COUNTER = 0x939
    MLX5_CMD_OP_DEALLOC_FLOW_COUNTER = 0x93a
    MLX5_CMD_OP_QUERY_FLOW_COUNTER = 0x93b
    MLX5_CMD_OP_CREATE_TIR = 0x900
    MLX5_CMD_OP_CREATE_EQ = 0x301
    MLX5_CMD_OP_MAD_IFC = 0x50d
    MLX5_CMD_OP_ACCESS_REGISTER_PAOS = 0x5006
    MLX5_CMD_OP_ACCESS_REG = 0x805
    MLX5_CMD_OP_CREATE_MKEY = 0x200


class ActionType:
    SET_ACTION = 0x1
    ADD_ACTION = 0x2
    COPY_ACTION = 0x3


class PRMPacket(Packet):

    def extract_padding(self, p):
        return "", p


# Common
class SwPas(PRMPacket):
    fields_desc = [
        IntField('pa_h', 0),
        BitField('pa_l', 0, 20),
        BitField('reserved1', 0, 12),
    ]


# PD
class AllocPdIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_ALLOC_PD),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        StrFixedLenField('reserved2', None, length=8),
    ]


class AllocPdOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        ByteField('reserved2', 0),
        BitField('pd', 0, 24),
        StrFixedLenField('reserved3', None, length=4),
    ]


# CQ
class CmdInputFieldSelectResizeCq(PRMPacket):
    fields_desc = [
        BitField('reserved1', 0, 28),
        BitField('umem', 0, 1),
        BitField('log_page_size', 0, 1),
        BitField('page_offset', 0, 1),
        BitField('log_cq_size', 0, 1),
    ]


class CmdInputFieldSelectModifyCqFields(PRMPacket):
    fields_desc = [
        BitField('reserved_0', 0, 26),
        BitField('status', 0, 1),
        BitField('cq_period_mode', 0, 1),
        BitField('c_eqn', 0, 1),
        BitField('oi', 0, 1),
        BitField('cq_max_count', 0, 1),
        BitField('cq_period', 0, 1),
    ]


class SwCqc(PRMPacket):
    fields_desc = [
        BitField('status', 0, 4),
        BitField('as_notify', 0, 1),
        BitField('initiator_src_dct', 0, 1),
        BitField('dbr_umem_valid', 0, 1),
        BitField('reserved1', 0, 1),
        BitField('cqe_sz', 0, 3),
        BitField('cc', 0, 1),
        BitField('reserved2', 0, 1),
        BitField('scqe_break_moderation_en', 0, 1),
        BitField('oi', 0, 1),
        BitField('cq_period_mode', 0, 2),
        BitField('cqe_compression_en', 0, 1),
        BitField('mini_cqe_res_format', 0, 2),
        BitField('st', 0, 4),
        ByteField('reserved3', 0),
        IntField('dbr_umem_id', 0),
        BitField('reserved4', 0, 20),
        BitField('page_offset', 0, 6),
        BitField('reserved5', 0, 6),
        BitField('reserved6', 0, 3),
        BitField('log_cq_size', 0, 5),
        BitField('uar_page', 0, 24),
        BitField('reserved7', 0, 4),
        BitField('cq_period', 0, 12),
        ShortField('cq_max_count', 0),
        BitField('reserved8', 0, 24),
        ByteField('c_eqn', 0),
        BitField('reserved9', 0, 3),
        BitField('log_page_size', 0, 5),
        BitField('reserved10', 0, 24),
        StrFixedLenField('reserved11', None, length=4),
        ByteField('reserved12', 0),
        BitField('last_notified_index', 0, 24),
        ByteField('reserved13', 0),
        BitField('last_solicit_index', 0, 24),
        ByteField('reserved14', 0),
        BitField('consumer_counter', 0, 24),
        ByteField('reserved15', 0),
        BitField('producer_counter', 0, 24),
        BitField('local_partition_id', 0, 12),
        BitField('process_id', 0, 20),
        ShortField('reserved16', 0),
        ShortField('thread_id', 0),
        IntField('db_record_addr_63_32', 0),
        BitField('db_record_addr_31_3', 0, 29),
        BitField('reserved17', 0, 3),
    ]


class CreateCqIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_CREATE_CQ),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        ByteField('reserved2', 0),
        BitField('cqn', 0, 24),
        StrFixedLenField('reserved3', None, length=4),
        PacketField('sw_cqc', SwCqc(), SwCqc),
        LongField('e_mtt_pointer_or_cq_umem_offset', 0),
        IntField('cq_umem_id', 0),
        BitField('cq_umem_valid', 0, 1),
        BitField('reserved4', 0, 31),
        StrFixedLenField('reserved5', None, length=176),
        PacketListField('pas', [SwPas() for x in range(0)], SwPas, count_from=lambda pkt: 0),
    ]


class CreateCqOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        ByteField('reserved2', 0),
        BitField('cqn', 0, 24),
        StrFixedLenField('reserved3', None, length=4),
    ]


# QP
class SwAds(PRMPacket):
    fields_desc = [
        BitField('fl', 0, 1),
        BitField('free_ar', 0, 1),
        BitField('reserved1', 0, 14),
        ShortField('pkey_index', 0),
        ByteField('reserved2', 0),
        BitField('grh', 0, 1),
        BitField('mlid', 0, 7),
        ShortField('rlid', 0),
        BitField('ack_timeout', 0, 5),
        BitField('reserved3', 0, 3),
        ByteField('src_addr_index', 0),
        BitField('log_rtm', 0, 4),
        BitField('stat_rate', 0, 4),
        ByteField('hop_limit', 0),
        BitField('reserved4', 0, 4),
        BitField('tclass', 0, 8),
        BitField('flow_label', 0, 20),
        FieldListField('rgid_rip', [0 for x in range(4)], IntField('', 0),
                       count_from=lambda pkt: 4),
        BitField('reserved5', 0, 4),
        BitField('f_dscp', 0, 1),
        BitField('f_ecn', 0, 1),
        BitField('reserved6', 0, 1),
        BitField('f_eth_prio', 0, 1),
        BitField('ecn', 0, 2),
        BitField('dscp', 0, 6),
        ShortField('udp_sport', 0),
        BitField('dei_cfi_reserved_from_prm_041', 0, 1),
        BitField('eth_prio', 0, 3),
        BitField('sl', 0, 4),
        ByteField('vhca_port_num', 0),
        MACField('rmac', '00:00:00:00:00:00'),

    ]


class SwQpc(PRMPacket):
    fields_desc = [
        BitField('state', 0, 4),
        BitField('lag_tx_port_affinity', 0, 4),
        ByteField('st', 0),
        BitField('reserved1', 0, 3),
        BitField('pm_state', 0, 2),
        BitField('reserved2', 0, 1),
        BitField('req_e2e_credit_mode', 0, 2),
        BitField('offload_type', 0, 4),
        BitField('end_padding_mode', 0, 2),
        BitField('reserved3', 0, 2),
        BitField('wq_signature', 0, 1),
        BitField('block_lb_mc', 0, 1),
        BitField('atomic_like_write_en', 0, 1),
        BitField('latency_sensitive', 0, 1),
        BitField('dual_write', 0, 1),
        BitField('drain_sigerr', 0, 1),
        BitField('multi_path', 0, 1),
        BitField('reserved4', 0, 1),
        BitField('pd', 0, 24),
        BitField('mtu', 0, 3),
        BitField('log_msg_max', 0, 5),
        BitField('reserved5', 0, 1),
        BitField('log_rq_size', 0, 4),
        BitField('log_rq_stride', 0, 3),
        BitField('no_sq', 0, 1),
        BitField('log_sq_size', 0, 4),
        BitField('reserved6', 0, 1),
        BitField('retry_mode', 0, 2),
        BitField('ts_format', 0, 2),
        BitField('data_in_order', 0, 1),
        BitField('rlkey', 0, 1),
        BitField('ulp_stateless_offload_mode', 0, 4),
        ByteField('counter_set_id', 0),
        BitField('uar_page', 0, 24),
        BitField('send_dbr_mode', 0, 2),
        BitField('reserved7', 0, 1),
        BitField('full_handshake', 0, 1),
        BitField('cnak_reverse_sl', 0, 4),
        BitField('user_index', 0, 24),
        BitField('reserved8', 0, 3),
        BitField('log_page_size', 0, 5),
        BitField('remote_qpn', 0, 24),
        PacketField('primary_address_path', SwAds(), SwAds),
        PacketField('secondary_address_path', SwAds(), SwAds),
        BitField('log_ack_req_freq', 0, 4),
        BitField('reserved9', 0, 4),
        BitField('log_sra_max', 0, 3),
        BitField('extended_rnr_retry_valid', 0, 1),
        BitField('reserved10', 0, 1),
        BitField('retry_count', 0, 3),
        BitField('rnr_retry', 0, 3),
        BitField('extended_retry_count_valid', 0, 1),
        BitField('fre', 0, 1),
        BitField('cur_rnr_retry', 0, 3),
        BitField('cur_retry_count', 0, 3),
        BitField('extended_log_rnr_retry', 0, 5),
        ShortField('extended_cur_rnr_retry', 0),
        ShortField('packet_pacing_rate_limit_index', 0),
        ByteField('reserved11', 0),
        BitField('next_send_psn', 0, 24),
        ByteField('reserved12', 0),
        BitField('cqn_snd', 0, 24),
        ByteField('reserved13', 0),
        BitField('deth_sqpn', 0, 24),
        ByteField('reserved14', 0),
        ByteField('extended_retry_count', 0),
        ByteField('reserved15', 0),
        ByteField('extended_cur_retry_count', 0),
        ByteField('reserved16', 0),
        BitField('last_acked_psn', 0, 24),
        ByteField('reserved17', 0),
        BitField('ssn', 0, 24),
        ByteField('reserved18', 0),
        BitField('log_rra_max', 0, 3),
        BitField('reserved19', 0, 1),
        BitField('atomic_mode', 0, 4),
        BitField('rre', 0, 1),
        BitField('rwe', 0, 1),
        BitField('rae', 0, 1),
        BitField('reserved20', 0, 1),
        BitField('page_offset', 0, 6),
        BitField('reserved21', 0, 3),
        BitField('cd_slave_receive', 0, 1),
        BitField('cd_slave_send', 0, 1),
        BitField('cd_master', 0, 1),
        BitField('reserved22', 0, 3),
        BitField('min_rnr_nak', 0, 5),
        BitField('next_rcv_psn', 0, 24),
        ByteField('reserved23', 0),
        BitField('xrcd', 0, 24),
        ByteField('reserved24', 0),
        BitField('cqn_rcv', 0, 24),
        LongField('dbr_addr', 0),
        IntField('q_key', 0),
        BitField('reserved25', 0, 5),
        BitField('rq_type', 0, 3),
        BitField('srqn_rmpn_xrqn', 0, 24),
        ByteField('reserved26', 0),
        BitField('rmsn', 0, 24),
        ShortField('hw_sq_wqebb_counter', 0),
        ShortField('sw_sq_wqebb_counter', 0),
        IntField('hw_rq_counter', 0),
        IntField('sw_rq_counter', 0),
        ByteField('reserved27', 0),
        BitField('roce_adp_retrans_rtt', 0, 24),
        BitField('reserved28', 0, 15),
        BitField('cgs', 0, 1),
        ByteField('cs_req', 0),
        ByteField('cs_res', 0),
        LongField('dc_access_key', 0),
        BitField('rdma_active', 0, 1),
        BitField('comm_est', 0, 1),
        BitField('suspended', 0, 1),
        BitField('dbr_umem_valid', 0, 1),
        BitField('reserved29', 0, 4),
        BitField('send_msg_psn', 0, 24),
        ByteField('reserved30', 0),
        BitField('rcv_msg_psn', 0, 24),
        LongField('rdma_va', 0),
        IntField('rdma_key', 0),
        IntField('dbr_umem_id', 0),
    ]


class CreateQpIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_CREATE_QP),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        ByteField('reserved2', 0),
        BitField('input_qpn', 0, 24),
        BitField('reserved3', 0, 1),
        BitField('cmd_on_behalf', 0, 1),
        BitField('reserved4', 0, 14),
        ShortField('vhca_id', 0),
        IntField('opt_param_mask', 0),
        StrFixedLenField('reserved5', None, length=4),
        PacketField('sw_qpc', SwQpc(), SwQpc),
        LongField('e_mtt_pointer_or_wq_umem_offset', 0),
        IntField('wq_umem_id', 0),
        BitField('wq_umem_valid', 0, 1),
        BitField('reserved6', 0, 31),
        PacketListField('pas', [SwPas() for x in range(0)], SwPas,
                        count_from=lambda pkt: 0),
    ]


class CreateQpOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        ByteField('reserved2', 0),
        BitField('qpn', 0, 24),
        StrFixedLenField('reserved3', None, length=4),
    ]


class ModifyQpIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', 0),
        ShortField('uid', 0),
        ShortField('vhca_tunnel_id', 0),
        ShortField('op_mod', 0),
        ByteField('reserved2', 0),
        BitField('qpn', 0, 24),
        IntField('reserved3', 0),
        IntField('opt_param_mask', 0),
        IntField('ece', 0),
        PacketField('sw_qpc', SwQpc(), SwQpc),
        StrFixedLenField('reserved4', None, length=16),
    ]


class ModifyQpOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
    ]


class QueryQpIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_QUERY_QP),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        ByteField('reserved2', 0),
        BitField('qpn', 0, 24),
        StrFixedLenField('reserved3', None, length=4),
    ]


class QueryQpOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        IntField('opt_param_mask', 0),
        StrFixedLenField('reserved3', None, length=4),
        PacketField('sw_qpc', SwQpc(), SwQpc),
        LongField('e_mtt_pointer', 0),
        StrFixedLenField('reserved4', None, length=8),
        PacketListField('pas', [SwPas() for x in range(0)], SwPas,
                        count_from=lambda pkt: 0),
    ]


# EQ
class SwEqc(PRMPacket):
    fields_desc = [
        BitField('status', 0, 4),
        BitField('reserved1', 0, 9),
        BitField('ec', 0, 1),
        BitField('oi', 0, 1),
        BitField('reserved2', 0, 5),
        BitField('st', 0, 4),
        ByteField('reserved3', 0),
        StrFixedLenField('reserved4', None, length=4),
        BitField('reserved5', 0, 20),
        BitField('page_offset', 0, 6),
        BitField('reserved6', 0, 6),
        BitField('reserved7', 0, 3),
        BitField('log_eq_size', 0, 5),
        BitField('uar_page', 0, 24),
        StrFixedLenField('reserved8', None, length=4),
        BitField('reserved9', 0, 20),
        BitField('intr', 0, 12),
        BitField('reserved10', 0, 3),
        BitField('log_page_size', 0, 5),
        BitField('reserved11', 0, 24),
        StrFixedLenField('reserved12', None, length=12),
        ByteField('reserved13', 0),
        BitField('consumer_counter', 0, 24),
        ByteField('reserved14', 0),
        BitField('producer_counter', 0, 24),
        StrFixedLenField('reserved15', None, length=16),
    ]


class CreateEqIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_CREATE_EQ),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        BitField('reserved2', 0, 24),
        ByteField('eqn', 0),
        StrFixedLenField('reserved3', None, length=4),
        PacketField('sw_eqc', SwEqc(), SwEqc),
        LongField('e_mtt_pointer', 0),
        LongField('event_bitmask_63_0', 0),
        LongField('event_bitmask_127_640', 0),
        LongField('event_bitmask_191_128', 0),
        LongField('event_bitmask_255_192', 0),
        StrFixedLenField('reserved4', None, length=152),
    ]


class CreateEqOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        BitField('reserved2', 0, 24),
        ByteField('eqn', 0),
        StrFixedLenField('reserved3', None, length=4),
    ]


class IbSmp(PRMPacket):
    fields_desc = [
        ByteField('base_version', 0),
        ByteField('mgmt_class', 0),
        ByteField('class_version', 0),
        ByteField('method', 0),
        ShortField('status', 0),
        ByteField('hop_ptr', 0),
        ByteField('hop_cnt', 0),
        LongField('tid', 0),
        ShortField('attr_id', 0),
        ShortField('resv', 0),
        IntField('attr_mod', 0),
        LongField('mkey', 0),
        ShortField('dr_slid', 0),
        ShortField('dr_dlid', 0),
        FieldListField('reserved', [0 for x in range(7)], IntField('', 0), count_from=lambda pkt: 7),
        FieldListField('data', [0 for x in range(64)], ByteField('', 0), count_from=lambda pkt: 64),
        FieldListField('initial_path', [0 for x in range(64)], ByteField('', 0), count_from=lambda pkt: 64),
        FieldListField('return_path', [0 for x in range(64)], ByteField('', 0), count_from=lambda pkt: 64),

    ]


class MadIfcIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_MAD_IFC),
        ShortField('uid', 0),

        ShortField('reserved1', 0),
        ShortField('op_mod', 0),

        ShortField('remote_lid', 0),
        ByteField('reserved2', 0),
        ByteField('port', 0),
        StrFixedLenField('reserved3', None, length=4),
        StrFixedLenField('mad', None, length=256),
    ]


class MadIfcOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        StrFixedLenField('mad', None, length=256),
    ]


class PaosReg(PRMPacket):
    fields_desc = [
        ByteField('swid', 0),
        ByteField('local_port', 0),
        BitField('reserved1', 0, 4),
        BitField('admin_status', 0, 4),
        BitField('reserved2', 0, 4),
        BitField('oper_status', 0, 4),
        BitField('ase', 0, 1),
        BitField('ee', 0, 1),
        BitField('reserved3', 0, 21),
        BitField('fd', 0, 1),
        BitField('reserved4', 0, 6),
        BitField('e', 0, 2),
        StrFixedLenField('reserved5', None, length=8),
    ]


class AccessPaosRegisterIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_ACCESS_REG),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        ShortField('reserved2', 0),
        ShortField('register_id', 0),
        IntField('argument', 0),
        PacketField('data', PaosReg(), PaosReg),
    ]


class AccessPaosRegisterOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        PacketField('data', PaosReg(), PaosReg),
    ]


# EQE
class EventType:
    COMPLETION_EVENTS = 0X0
    CQ_ERROR = 0X4
    PORT_STATE_CHANGE = 0X9


class AffiliatedEventHeader(PRMPacket):
    fields_desc = [
        ShortField('reserved1', 0),
        ShortField('obj_type', 0),
        IntField('obj_id', 0),
    ]


class CompEvent(PRMPacket):
    fields_desc = [
        StrFixedLenField('reserved1', None, length=24),
        ByteField('reserved2', 0),
        BitField('cqn', 0, 24),
    ]


class CqError(PRMPacket):
    fields_desc = [
        ByteField('reserved1', 0),
        BitField('cqn', 0, 24),
        StrFixedLenField('reserved2', None, length=4),
        BitField('reserved3', 0, 24),
        ByteField('syndrome', 0),
        StrFixedLenField('reserved4', None, length=16),
    ]


class PortStateChangeEvent(PRMPacket):
    fields_desc = [
        StrFixedLenField('reserved1', None, length=8),
        BitField('port_num', 0, 4),
        BitField('reserved2', 0, 28),
        StrFixedLenField('reserved3', None, length=16),
    ]


class SwEqe(PRMPacket):
    fields_desc = [
        ByteField('reserved1', 0),
        ByteField('event_type', 0),
        ByteField('reserved2', 0),
        ByteField('event_sub_type', 0),
        StrFixedLenField('reserved3', None, length=28),
        MultipleTypeField(
            [
                (PadField(PacketField('event_data', CompEvent(), CompEvent), 28, padwith=b"\x00"),
                 lambda pkt: pkt.event_type == EventType.COMPLETION_EVENTS),
                (PadField(PacketField('event_data', CqError(), CqError), 28, padwith=b"\x00"),
                 lambda pkt: pkt.event_type == EventType.CQ_ERROR),
                (PadField(PacketField('event_data', PortStateChangeEvent(), PortStateChangeEvent), 28, padwith=b"\x00"),
                 lambda pkt: pkt.event_type == EventType.PORT_STATE_CHANGE),
            ],
            StrFixedLenField('event_data', None, length=28)  # By default
        ),
        ShortField('reserved4', 0),
        ByteField('signature', 0),
        BitField('reserved5', 0, 7),
        BitField('owner', 0, 1),
    ]


# Query HCA VPORT Context
class QueryHcaVportContextIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        BitField('other_vport', 0, 1),
        BitField('reserved2', 0, 11),
        BitField('port_num', 0, 4),
        ShortField('vport_number', 0),
        StrFixedLenField('reserved3', None, length=4),
    ]


class HcaVportContext(PRMPacket):
    fields_desc = [
        IntField('field_select', 0),
        StrFixedLenField('reserved1', None, length=28),
        BitField('sm_virt_aware', 0, 1),
        BitField('has_smi', 0, 1),
        BitField('has_raw', 0, 1),
        BitField('grh_required', 0, 1),
        BitField('reserved2', 0, 1),
        BitField('min_wqe_inline_mode', 0, 3),
        ByteField('reserved3', 0),
        BitField('port_physical_state', 0, 4),
        BitField('vport_state_policy', 0, 4),
        BitField('port_state', 0, 4),
        BitField('vport_state', 0, 4),
        StrFixedLenField('reserved4', None, length=4),
        LongField('system_image_guid', 0),
        LongField('port_guid', 0),
        LongField('node_guid', 0),
        IntField('cap_mask1', 0),
        IntField('cap_mask1_field_select', 0),
        IntField('cap_mask2', 0),
        IntField('cap_mask2_field_select', 0),
        ShortField('reserved5', 0),
        ShortField('ooo_sl_mask', 0),
        StrFixedLenField('reserved6', None, length=12),
        ShortField('lid', 0),
        BitField('reserved7', 0, 4),
        BitField('init_type_reply', 0, 4),
        BitField('lmc', 0, 3),
        BitField('subnet_timeout', 0, 5),
        ShortField('sm_lid', 0),
        BitField('sm_sl', 0, 4),
        BitField('reserved8', 0, 12),
        ShortField('qkey_violation_counter', 0),
        ShortField('pkey_violation_counter', 0),
        StrFixedLenField('reserved9', None, length=404),
    ]


class QueryHcaVportContextOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        PacketField('hca_vport_context', HcaVportContext(), HcaVportContext),
    ]


# Query HCA VPORT GID
class QueryHcaVportGidIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_QUERY_HCA_VPORT_GID),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        BitField('other_vport', 0, 1),
        BitField('reserved2', 0, 11),
        BitField('port_num', 0, 4),
        ShortField('vport_number', 0),
        ShortField('reserved3', 0),
        ShortField('gid_index', 0),
    ]


class IbGidCmd(PRMPacket):
    fields_desc = [
        LongField('prefix', 0),
        LongField('guid', 0),
    ]


class QueryHcaVportGidOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=4),
        ShortField('gids_num', 0),
        ShortField('reserved3', 0),
        PacketField('gid0', IbGidCmd(), IbGidCmd),
    ]


class QueryHcaCapOp:
    HCA_CAP_2 = 0X20
    HCA_NIC_FLOW_TABLE_CAP = 0x7


class QueryHcaCapMod:
    MAX = 0x0
    CURRENT = 0x1


class SendDbrMode:
    DBR_VALID = 0x0
    NO_DBR_EXT = 0x1
    NO_DBR_INT = 0x2


# Query HCA CAP
class QueryHcaCapIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_QUERY_HCA_CAP),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        BitField('other_function', 0, 1),
        BitField('reserved2', 0, 15),
        ShortField('function_id', 0),
        StrFixedLenField('reserved3', None, length=4),
    ]


class CmdHcaCap(PRMPacket):
    fields_desc = [
        BitField('access_other_hca_roce', 0, 1),
        BitField('reserved1', 0, 30),
        BitField('vhca_resource_manager', 0, 1),
        BitField('hca_cap_2', 0, 1),
        BitField('reserved2', 0, 2),
        BitField('event_on_vhca_state_teardown_request', 0, 1),
        BitField('event_on_vhca_state_in_use', 0, 1),
        BitField('event_on_vhca_state_active', 0, 1),
        BitField('event_on_vhca_state_allocated', 0, 1),
        BitField('event_on_vhca_state_invalid', 0, 1),
        ByteField('transpose_max_element_size', 0),
        ShortField('vhca_id', 0),
        ByteField('transpose_max_cols', 0),
        ByteField('transpose_max_rows', 0),
        ShortField('transpose_max_size', 0),
        BitField('reserved3', 0, 1),
        BitField('sw_steering_icm_large_scale_steering', 0, 1),
        BitField('qp_data_in_order', 0, 1),
        BitField('log_regexp_scatter_gather_size', 0, 5),
        BitField('reserved4', 0, 3),
        BitField('log_dma_mmo_max_size', 0, 5),
        BitField('relaxed_ordering_write_pci_enabled', 0, 1),
        BitField('reserved5', 0, 2),
        BitField('log_compress_max_size', 0, 5),
        BitField('reserved6', 0, 3),
        BitField('log_decompress_max_size', 0, 5),
        ByteField('log_max_srq_sz', 0),
        ByteField('log_max_qp_sz', 0),
        BitField('event_cap', 0, 1),
        BitField('reserved7', 0, 2),
        BitField('isolate_vl_tc_new', 0, 1),
        BitField('reserved8', 0, 2),
        BitField('nvmeotcp', 0, 1),
        BitField('pcie_hanged', 0, 1),
        BitField('prio_tag_required', 0, 1),
        BitField('wqe_index_ignore_cap', 0, 1),
        BitField('reserved9', 0, 1),
        BitField('log_max_qp', 0, 5),
        BitField('regexp', 0, 1),
        BitField('regexp_params', 0, 1),
        BitField('regexp_alloc_onbehalf_umem', 0, 1),
        BitField('ece', 0, 1),
        BitField('regexp_num_of_engines', 0, 4),
        BitField('allow_pause_tx', 0, 1),
        BitField('reg_c_preserve', 0, 1),
        BitField('isolate_vl_tc', 0, 1),
        BitField('log_max_srqs', 0, 5),
        BitField('psp', 0, 1),
        BitField('reserved10', 0, 1),
        BitField('ts_cqe_to_dest_cqn', 0, 1),
        BitField('regexp_log_crspace_size', 0, 5),
        BitField('selective_repeat', 0, 1),
        BitField('go_back_n', 0, 1),
        BitField('reserved11', 0, 1),
        BitField('scatter_fcs_w_decap_disable', 0, 1),
        BitField('reserved12', 0, 4),
        ByteField('max_sgl_for_optimized_performance', 0),
        ByteField('log_max_cq_sz', 0),
        BitField('relaxed_ordering_write_umr', 0, 1),
        BitField('relaxed_ordering_read_umr', 0, 1),
        BitField('access_register_user', 0, 1),
        BitField('reserved13', 0, 5),
        BitField('upt_device_emulation_manager', 0, 1),
        BitField('virtio_net_device_emulation_manager', 0, 1),
        BitField('virtio_blk_device_emulation_manager', 0, 1),
        BitField('log_max_cq', 0, 5),
        ByteField('log_max_eq_sz', 0),
        BitField('relaxed_ordering_write', 0, 1),
        BitField('relaxed_ordering_read', 0, 1),
        BitField('log_max_mkey', 0, 6),
        BitField('tunneled_atomic', 0, 1),
        BitField('as_notify', 0, 1),
        BitField('m_pci_port', 0, 1),
        BitField('m_vhca_mk', 0, 1),
        BitField('hotplug_manager', 0, 1),
        BitField('nvme_device_emulation_manager', 0, 1),
        BitField('terminate_scatter_list_mkey', 0, 1),
        BitField('repeated_mkey', 0, 1),
        BitField('dump_fill_mkey', 0, 1),
        BitField('dpp', 0, 1),
        BitField('resources_on_nvme_emulation_manager', 0, 1),
        BitField('fast_teardown', 0, 1),
        BitField('log_max_eq', 0, 4),
        ByteField('max_indirection', 0),
        BitField('fixed_buffer_size', 0, 1),
        BitField('log_max_mrw_sz', 0, 7),
        BitField('force_teardown', 0, 1),
        BitField('prepare_fast_teardown_allways_1', 0, 1),
        BitField('log_max_bsf_list_size', 0, 6),
        BitField('umr_extended_translation_offset', 0, 1),
        BitField('null_mkey', 0, 1),
        BitField('log_max_klm_list_size', 0, 6),
        BitField('non_wire_sq', 0, 1),
        BitField('ats_ro_dependence', 0, 1),
        BitField('qp_context_extension', 0, 1),
        BitField('log_max_static_sq_wq_size', 0, 5),
        BitField('resources_on_virtio_net_emulation_manager', 0, 1),
        BitField('resources_on_virtio_blk_emulation_manager', 0, 1),
        BitField('log_max_ra_req_dc', 0, 6),
        BitField('vhca_trust_level_reg', 0, 1),
        BitField('eth_wqe_too_small_mode', 0, 1),
        BitField('vnic_env_eth_wqe_too_small', 0, 1),
        BitField('log_max_static_sq_wq', 0, 5),
        BitField('ooo_sl_mask', 0, 1),
        BitField('vnic_env_cq_overrun', 0, 1),
        BitField('log_max_ra_res_dc', 0, 6),
        BitField('cc_roce_ecn_rp_classify_mode', 0, 1),
        BitField('cc_roce_ecn_rp_dynamic_rtt', 0, 1),
        BitField('cc_roce_ecn_rp_dynamic_ai', 0, 1),
        BitField('cc_roce_ecn_rp_dynamic_g', 0, 1),
        BitField('cc_roce_ecn_rp_burst_decouple', 0, 1),
        BitField('release_all_pages', 0, 1),
        BitField('depracated_do_not_use', 0, 1),
        BitField('sig_crc64_xp10', 0, 1),
        BitField('sig_crc32c', 0, 1),
        BitField('roce_accl', 0, 1),
        BitField('log_max_ra_req_qp', 0, 6),
        BitField('reserved14', 0, 1),
        BitField('rts2rts_udp_sport', 0, 1),
        BitField('rts2rts_lag_tx_port_affinity', 0, 1),
        BitField('dma_mmo', 0, 1),
        BitField('compress_min_block_size', 0, 4),
        BitField('compress', 0, 1),
        BitField('decompress', 0, 1),
        BitField('log_max_ra_res_qp', 0, 6),
        BitField('end_pad', 0, 1),
        BitField('cc_query_allowed', 0, 1),
        BitField('cc_modify_allowed', 0, 1),
        BitField('start_pad', 0, 1),
        BitField('cache_line_128byte', 0, 1),
        BitField('gid_table_size_ro', 0, 1),
        BitField('pkey_table_size_ro', 0, 1),
        BitField('rts2rts_qp_rmp', 0, 1),
        BitField('rnr_nak_q_counters', 0, 1),
        BitField('rts2rts_qp_counters_set_id', 0, 1),
        BitField('rts2rts_qp_dscp', 0, 1),
        BitField('gen3_cc_negotiation', 0, 1),
        BitField('vnic_env_int_rq_oob', 0, 1),
        BitField('sbcam_reg', 0, 1),
        BitField('cwcam_reg', 0, 1),
        BitField('qcam_reg', 0, 1),
        ShortField('gid_table_size', 0),
        BitField('out_of_seq_cnt', 0, 1),
        BitField('vport_counters', 0, 1),
        BitField('retransmission_q_counters', 0, 1),
        BitField('debug', 0, 1),
        BitField('modify_rq_counters_set_id', 0, 1),
        BitField('rq_delay_drop', 0, 1),
        BitField('max_qp_cnt', 0, 10),
        ShortField('pkey_table_size', 0),
        BitField('vport_group_manager', 0, 1),
        BitField('vhca_group_manager', 0, 1),
        BitField('ib_virt', 0, 1),
        BitField('eth_virt', 0, 1),
        BitField('vnic_env_queue_counters', 0, 1),
        BitField('ets', 0, 1),
        BitField('nic_flow_table', 0, 1),
        BitField('eswitch_manager', 0, 1),
        BitField('device_memory', 0, 1),
        BitField('mcam_reg', 0, 1),
        BitField('pcam_reg', 0, 1),
        BitField('local_ca_ack_delay', 0, 5),
        BitField('port_module_event', 0, 1),
        BitField('enhanced_retransmission_q_counters', 0, 1),
        BitField('port_checks', 0, 1),
        BitField('pulse_gen_control', 0, 1),
        BitField('disable_link_up_by_init_hca', 0, 1),
        BitField('beacon_led', 0, 1),
        BitField('port_type', 0, 2),
        ByteField('num_ports', 0),
        BitField('snapshot', 0, 1),
        BitField('pps', 0, 1),
        BitField('pps_modify', 0, 1),
        BitField('log_max_msg', 0, 5),
        BitField('multi_path_xrc_rdma', 0, 1),
        BitField('multi_path_dc_rdma', 0, 1),
        BitField('multi_path_rc_rdma', 0, 1),
        BitField('traffic_fast_control', 0, 1),
        BitField('max_tc', 0, 4),
        BitField('temp_warn_event', 0, 1),
        BitField('dcbx', 0, 1),
        BitField('general_notification_event', 0, 1),
        BitField('multi_prio_sq', 0, 1),
        BitField('afu_owner', 0, 1),
        BitField('fpga', 0, 1),
        BitField('rol_s', 0, 1),
        BitField('rol_g', 0, 1),
        BitField('ib_port_sniffer', 0, 1),
        BitField('wol_s', 0, 1),
        BitField('wol_g', 0, 1),
        BitField('wol_a', 0, 1),
        BitField('wol_b', 0, 1),
        BitField('wol_m', 0, 1),
        BitField('wol_u', 0, 1),
        BitField('wol_p', 0, 1),
        ShortField('stat_rate_support', 0),
        BitField('sig_block_4048', 0, 1),
        BitField('pci_sync_for_fw_update_event', 0, 1),
        BitField('init2rtr_drain_sigerr', 0, 1),
        BitField('log_max_extended_rnr_retry', 0, 5),
        BitField('init2_lag_tx_port_affinity', 0, 1),
        BitField('flow_group_type_hash_split', 0, 1),
        BitField('reserved15', 0, 1),
        BitField('wqe_based_flow_table_update', 0, 1),
        BitField('cqe_version', 0, 4),
        BitField('compact_address_vector', 0, 1),
        BitField('eth_striding_wq', 0, 1),
        BitField('reserved16', 0, 1),
        BitField('ipoib_enhanced_offloads', 0, 1),
        BitField('ipoib_basic_offloads', 0, 1),
        BitField('ib_link_list_striding_wq', 0, 1),
        BitField('repeated_block_disabled', 0, 1),
        BitField('umr_modify_entity_size_disabled', 0, 1),
        BitField('umr_modify_atomic_disabled', 0, 1),
        BitField('umr_indirect_mkey_disabled', 0, 1),
        BitField('umr_fence', 0, 2),
        BitField('dc_req_sctr_data_cqe', 0, 1),
        BitField('dc_connect_qp', 0, 1),
        BitField('dc_cnak_trace', 0, 1),
        BitField('drain_sigerr', 0, 1),
        BitField('cmdif_checksum', 0, 2),
        BitField('sigerr_cqe', 0, 1),
        BitField('e_psv', 0, 1),
        BitField('wq_signature', 0, 1),
        BitField('sctr_data_cqe', 0, 1),
        BitField('bsf_in_create_mkey', 0, 1),
        BitField('sho', 0, 1),
        BitField('tph', 0, 1),
        BitField('rf', 0, 1),
        BitField('dct', 0, 1),
        BitField('qos', 0, 1),
        BitField('eth_net_offloads', 0, 1),
        BitField('roce', 0, 1),
        BitField('atomic', 0, 1),
        BitField('extended_retry_count', 0, 1),
        BitField('cq_oi', 0, 1),
        BitField('cq_resize', 0, 1),
        BitField('cq_moderation', 0, 1),
        BitField('cq_period_mode_modify', 0, 1),
        BitField('cq_invalidate', 0, 1),
        BitField('reserved17', 0, 1),
        BitField('cq_eq_remap', 0, 1),
        BitField('pg', 0, 1),
        BitField('block_lb_mc', 0, 1),
        BitField('exponential_backoff', 0, 1),
        BitField('scqe_break_moderation', 0, 1),
        BitField('cq_period_start_from_cqe', 0, 1),
        BitField('cd', 0, 1),
        BitField('atm', 0, 1),
        BitField('apm', 0, 1),
        BitField('vector_calc', 0, 1),
        BitField('umr_ptr_rlkey', 0, 1),
        BitField('imaicl', 0, 1),
        BitField('qp_packet_based', 0, 1),
        BitField('ib_cyclic_striding_wq', 0, 1),
        BitField('ipoib_enhanced_pkey_change', 0, 1),
        BitField('initiator_src_dct_in_cqe', 0, 1),
        BitField('qkv', 0, 1),
        BitField('pkv', 0, 1),
        BitField('set_deth_sqpn', 0, 1),
        BitField('rts2rts_primary_sl', 0, 1),
        BitField('initiator_src_dct', 0, 1),
        BitField('dc_v2', 0, 1),
        BitField('xrc', 0, 1),
        BitField('ud', 0, 1),
        BitField('uc', 0, 1),
        BitField('rc', 0, 1),
        BitField('uar_4k', 0, 1),
        BitField('reserved18', 0, 7),
        BitField('fl_rc_qp_when_roce_disabled', 0, 1),
        BitField('reserved19', 0, 1),
        BitField('uar_sz', 0, 6),
        BitField('reserved20', 0, 3),
        BitField('log_max_dc_cnak_qps', 0, 5),
        ByteField('log_pg_sz', 0),
        BitField('bf', 0, 1),
        BitField('driver_version', 0, 1),
        BitField('pad_tx_eth_packet', 0, 1),
        BitField('query_driver_version', 0, 1),
        BitField('max_qp_retry_freq', 0, 1),
        BitField('qp_by_name', 0, 1),
        BitField('mkey_by_name', 0, 1),
        BitField('reserved21', 0, 4),
        BitField('log_bf_reg_size', 0, 5),
        BitField('reserved22', 0, 6),
        BitField('lag_dct', 0, 2),
        BitField('lag_tx_port_affinity', 0, 1),
        BitField('lag_native_fdb_selection', 0, 1),
        BitField('must_be_0', 0, 1),
        BitField('lag_master', 0, 1),
        BitField('num_lag_ports', 0, 4),
        ShortField('num_of_diagnostic_counters', 0),
        ShortField('max_wqe_sz_sq', 0),
        ShortField('reserved23', 0),
        ShortField('max_wqe_sz_rq', 0),
        ShortField('max_flow_counter_31_16', 0),
        ShortField('max_wqe_sz_sq_dc', 0),
        BitField('reserved24', 0, 7),
        BitField('max_qp_mcg', 0, 25),
        ShortField('mlnx_tag_ethertype', 0),
        ByteField('flow_counter_bulk_alloc', 0),
        ByteField('log_max_mcg', 0),
        BitField('reserved25', 0, 3),
        BitField('log_max_transport_domain', 0, 5),
        BitField('reserved26', 0, 3),
        BitField('log_max_pd', 0, 5),
        BitField('reserved27', 0, 11),
        BitField('log_max_xrcd', 0, 5),
        BitField('nic_receive_steering_discard', 0, 1),
        BitField('receive_discard_vport_down', 0, 1),
        BitField('transmit_discard_vport_down', 0, 1),
        BitField('eq_overrun_count', 0, 1),
        BitField('nic_receive_steering_depth', 0, 1),
        BitField('invalid_command_count', 0, 1),
        BitField('quota_exceeded_count', 0, 1),
        BitField('flow_counter_by_name', 0, 1),
        ByteField('log_max_flow_counter_bulk', 0),
        ShortField('max_flow_counter_15_0', 0),
        BitField('modify_tis', 0, 1),
        BitField('flow_counters_dump', 0, 1),
        BitField('reserved28', 0, 1),
        BitField('log_max_rq', 0, 5),
        BitField('reserved29', 0, 3),
        BitField('log_max_sq', 0, 5),
        BitField('reserved30', 0, 3),
        BitField('log_max_tir', 0, 5),
        BitField('reserved31', 0, 3),
        BitField('log_max_tis', 0, 5),
        BitField('basic_cyclic_rcv_wqe', 0, 1),
        BitField('reserved32', 0, 2),
        BitField('log_max_rmp', 0, 5),
        BitField('reserved33', 0, 3),
        BitField('log_max_rqt', 0, 5),
        BitField('reserved34', 0, 3),
        BitField('log_max_rqt_size', 0, 5),
        BitField('reserved35', 0, 3),
        BitField('log_max_tis_per_sq', 0, 5),
        BitField('ext_stride_num_range', 0, 1),
        BitField('reserved36', 0, 2),
        BitField('log_max_stride_sz_rq', 0, 5),
        BitField('reserved37', 0, 3),
        BitField('log_min_stride_sz_rq', 0, 5),
        BitField('reserved38', 0, 3),
        BitField('log_max_stride_sz_sq', 0, 5),
        BitField('reserved39', 0, 3),
        BitField('log_min_stride_sz_sq', 0, 5),
        BitField('hairpin_eth_raw', 0, 1),
        BitField('reserved40', 0, 2),
        BitField('log_max_hairpin_queues', 0, 5),
        BitField('hairpin_ib_raw', 0, 1),
        BitField('hairpin_eth2ipoib', 0, 1),
        BitField('hairpin_ipoib2eth', 0, 1),
        BitField('log_max_hairpin_wq_data_sz', 0, 5),
        BitField('reserved41', 0, 3),
        BitField('log_max_hairpin_num_packets', 0, 5),
        BitField('reserved42', 0, 3),
        BitField('log_max_wq_sz', 0, 5),
        BitField('nic_vport_change_event', 0, 1),
        BitField('disable_local_lb_uc', 0, 1),
        BitField('disable_local_lb_mc', 0, 1),
        BitField('log_min_hairpin_wq_data_sz', 0, 5),
        BitField('system_image_guid_modifiable', 0, 1),
        BitField('reserved43', 0, 1),
        BitField('vhca_state', 0, 1),
        BitField('log_max_vlan_list', 0, 5),
        BitField('reserved44', 0, 3),
        BitField('log_max_current_mc_list', 0, 5),
        BitField('reserved45', 0, 3),
        BitField('log_max_current_uc_list', 0, 5),
        LongField('general_obj_types', 0),
        BitField('sq_ts_format', 0, 2),
        BitField('rq_ts_format', 0, 2),
        BitField('steering_format_version', 0, 4),
        BitField('create_qp_start_hint', 0, 24),
        BitField('tls', 0, 1),
        BitField('ats', 0, 1),
        BitField('reserved46', 0, 1),
        BitField('log_max_uctx', 0, 5),
        BitField('aes_xts', 0, 1),
        BitField('crypto', 0, 1),
        BitField('ipsec_offload', 0, 1),
        BitField('log_max_umem', 0, 5),
        ShortField('max_num_eqs', 0),
        BitField('reserved47', 0, 1),
        BitField('tls_tx', 0, 1),
        BitField('tls_rx', 0, 1),
        BitField('log_max_l2_table', 0, 5),
        ByteField('reserved48', 0),
        ShortField('log_uar_page_sz', 0),
        BitField('e', 0, 1),
        BitField('reserved49', 0, 31),
        IntField('device_frequency_mhz', 0),
        IntField('device_frequency_khz', 0),
        BitField('capi', 0, 1),
        BitField('create_pec', 0, 1),
        BitField('nvmf_target_offload', 0, 1),
        BitField('capi_invalidate', 0, 1),
        BitField('reserved50', 0, 23),
        BitField('log_max_pasid', 0, 5),
        IntField('num_of_uars_per_page', 0),
        IntField('flex_parser_protocols', 0),
        ByteField('max_geneve_tlv_options', 0),
        BitField('reserved51', 0, 3),
        BitField('max_geneve_tlv_option_data_len', 0, 5),
        BitField('flex_parser_header_modify', 0, 1),
        BitField('reserved52', 0, 2),
        BitField('log_max_guaranteed_connections', 0, 5),
        BitField('reserved53', 0, 3),
        BitField('log_max_dct_connections', 0, 5),
        ByteField('log_max_atomic_size_qp', 0),
        BitField('reserved54', 0, 3),
        BitField('log_max_dci_stream_channels', 0, 5),
        BitField('reserved55', 0, 3),
        BitField('log_max_dci_errored_streams', 0, 5),
        ByteField('log_max_atomic_size_dc', 0),
        ShortField('max_multi_user_group_size', 0),
        BitField('reserved56', 0, 2),
        BitField('crossing_vhca_mkey', 0, 1),
        BitField('log_max_dek', 0, 5),
        BitField('reserved57', 0, 1),
        BitField('mini_cqe_resp_l3l4header', 0, 1),
        BitField('mini_cqe_resp_flow_tag', 0, 1),
        BitField('enhanced_cqe_compression', 0, 1),
        BitField('mini_cqe_resp_stride_index', 0, 1),
        BitField('cqe_128_always', 0, 1),
        BitField('cqe_compression_128b', 0, 1),
        BitField('cqe_compression', 0, 1),
        ShortField('cqe_compression_timeout', 0),
        ShortField('cqe_compression_max_num', 0),
        BitField('reserved58', 0, 3),
        BitField('wqe_based_flow_table_update_dest_type_offset', 0, 5),
        BitField('flex_parser_id_gtpu_dw_0', 0, 4),
        BitField('log_max_tm_offloaded_op_size', 0, 4),
        BitField('tag_matching', 0, 1),
        BitField('rndv_offload_rc', 0, 1),
        BitField('rndv_offload_dc', 0, 1),
        BitField('log_tag_matching_list_sz', 0, 5),
        BitField('reserved59', 0, 3),
        BitField('log_max_xrq', 0, 5),
        ByteField('affiliate_nic_vport_criteria', 0),
        ByteField('native_port_num', 0),
        ByteField('num_vhca_ports', 0),
        BitField('flex_parser_id_gtpu_teid', 0, 4),
        BitField('reserved60', 0, 1),
        BitField('trusted_vnic_vhca', 0, 1),
        BitField('sw_owner_id', 0, 1),
        BitField('reserve_not_to_use', 0, 1),
        ShortField('max_num_of_monitor_counters', 0),
        ShortField('num_ppcnt_monitor_counters', 0),
        ShortField('max_num_sf', 0),
        ShortField('num_q_monitor_counters', 0),
        StrFixedLenField('reserved61', None, length=4),
        BitField('sf', 0, 1),
        BitField('sf_set_partition', 0, 1),
        BitField('reserved62', 0, 1),
        BitField('log_max_sf', 0, 5),
        ByteField('reserved63', 0),
        ByteField('log_min_sf_size', 0),
        ByteField('max_num_sf_partitions', 0),
        IntField('uctx_permission', 0),
        BitField('flex_parser_id_mpls_over_x_cw', 0, 4),
        BitField('flex_parser_id_geneve_tlv_option_0', 0, 4),
        BitField('flex_parser_id_icmp_dw1', 0, 4),
        BitField('flex_parser_id_icmp_dw0', 0, 4),
        BitField('flex_parser_id_icmpv6_dw1', 0, 4),
        BitField('flex_parser_id_icmpv6_dw0', 0, 4),
        BitField('flex_parser_id_outer_first_mpls_over_gre', 0, 4),
        BitField('flex_parser_id_outer_first_mpls_over_udp_label', 0, 4),
        ShortField('max_num_match_definer', 0),
        ShortField('sf_base_id', 0),
        BitField('flex_parser_id_gtpu_dw_2', 0, 4),
        BitField('flex_parser_id_gtpu_first_ext_dw_0', 0, 4),
        BitField('num_total_dynamic_vf_msix', 0, 24),
        BitField('reserved64', 0, 3),
        BitField('log_flow_hit_aso_granularity', 0, 5),
        BitField('reserved65', 0, 3),
        BitField('log_flow_hit_aso_max_alloc', 0, 5),
        BitField('reserved66', 0, 4),
        BitField('dynamic_msix_table_size', 0, 12),
        BitField('reserved67', 0, 3),
        BitField('log_max_num_flow_hit_aso', 0, 5),
        BitField('reserved68', 0, 4),
        BitField('min_dynamic_vf_msix_table_size', 0, 4),
        BitField('reserved69', 0, 4),
        BitField('max_dynamic_vf_msix_table_size', 0, 12),
        BitField('reserved70', 0, 3),
        BitField('log_max_num_header_modify_argument', 0, 5),
        BitField('reserved71', 0, 4),
        BitField('log_header_modify_argument_granularity', 0, 4),
        BitField('reserved72', 0, 3),
        BitField('log_header_modify_argument_max_alloc', 0, 5),
        BitField('reserved73', 0, 3),
        BitField('max_flow_execute_aso', 0, 5),
        LongField('vhca_tunnel_commands', 0),
        LongField('match_definer_format_supported', 0),
    ]


class QueryCmdHcaCapOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        PadField(PacketField('capability', CmdHcaCap(), CmdHcaCap), 2048, padwith=b"\x00"),
    ]


class FlowTableEntryMatchSetMisc(PRMPacket):
    fields_desc = [
        BitField('gre_c_present', 0, 1),
        BitField('bth_a', 0, 1),
        BitField('gre_k_present', 0, 1),
        BitField('gre_s_present', 0, 1),
        BitField('source_vhca_port', 0, 4),
        BitField('source_sqn', 0, 24),
        ShortField('src_esw_owner_vhca_id', 0),
        ShortField('source_port', 0),
        BitField('outer_second_prio', 0, 3),
        BitField('outer_second_cfi', 0, 1),
        BitField('outer_second_vid', 0, 12),
        BitField('inner_second_prio', 0, 3),
        BitField('inner_second_cfi', 0, 1),
        BitField('inner_second_vid', 0, 12),
        BitField('outer_second_cvlan_tag', 0, 1),
        BitField('inner_second_cvlan_tag', 0, 1),
        BitField('outer_second_svlan_tag', 0, 1),
        BitField('inner_second_svlan_tag', 0, 1),
        BitField('outer_emd_tag', 0, 1),
        BitField('reserved2', 0, 11),
        ShortField('gre_protocol', 0),
        BitField('gre_key_h', 0, 24),
        ByteField('gre_key_l', 0),
        BitField('vxlan_vni', 0, 24),
        ByteField('bth_opcode', 0),
        BitField('geneve_vni', 0, 24),
        BitField('reserved4', 0, 7),
        BitField('geneve_oam', 0, 1),
        BitField('reserved5', 0, 12),
        BitField('outer_ipv6_flow_label', 0, 20),
        BitField('reserved6', 0, 12),
        BitField('inner_ipv6_flow_label', 0, 20),
        BitField('reserved7', 0, 10),
        BitField('geneve_opt_len', 0, 6),
        ShortField('geneve_protocol_type', 0),
        ByteField('reserved8', 0),
        BitField('bth_dst_qp', 0, 24),
        IntField('inner_esp_spi', 0),
        IntField('outer_esp_spi', 0),
        StrFixedLenField('reserved9', None, length=4),
        IntField('outer_emd_tag_data_47_16', 0),
        ShortField('outer_emd_tag_data_15_0', 0),
        ShortField('reserved10', 0),
    ]


class FlowTableEntryMatchSetMisc2(PRMPacket):
    fields_desc = [
        BitField('outer_first_mpls_label', 0, 20),
        BitField('outer_first_mpls_exp', 0, 3),
        BitField('outer_first_mpls_s_bos', 0, 1),
        ByteField('outer_first_mpls_ttl', 0),
        BitField('inner_first_mpls_label', 0, 20),
        BitField('inner_first_mpls_exp', 0, 3),
        BitField('inner_first_mpls_s_bos', 0, 1),
        ByteField('inner_first_mpls_ttl', 0),
        BitField('outer_last_mpls_over_gre_label', 0, 20),
        BitField('outer_last_mpls_over_gre_exp', 0, 3),
        BitField('outer_last_mpls_over_gre_s_bos', 0, 1),
        ByteField('outer_last_mpls_over_gre_ttl', 0),
        BitField('outer_last_mpls_over_udp_label', 0, 20),
        BitField('outer_last_mpls_over_udp_exp', 0, 3),
        BitField('outer_last_mpls_over_udp_s_bos', 0, 1),
        ByteField('outer_last_mpls_over_udp_ttl', 0),
        IntField('metadata_reg_c_7', 0),
        IntField('metadata_reg_c_6', 0),
        IntField('metadata_reg_c_5', 0),
        IntField('metadata_reg_c_4', 0),
        IntField('metadata_reg_c_3', 0),
        IntField('metadata_reg_c_2', 0),
        IntField('metadata_reg_c_1', 0),
        IntField('metadata_reg_c_0', 0),
        IntField('metadata_reg_a', 0),
        IntField('metadata_reg_b', 0),
        StrFixedLenField('reserved1', None, length=8),
    ]


class FlowTableEntryMatchSetMisc3(PRMPacket):
    fields_desc = [
        IntField('inner_tcp_seq_num', 0),
        IntField('outer_tcp_seq_num', 0),
        IntField('inner_tcp_ack_num', 0),
        IntField('outer_tcp_ack_num', 0),
        ByteField('reserved1', 0),
        BitField('outer_vxlan_gpe_vni', 0, 24),
        ByteField('outer_vxlan_gpe_next_protocol', 0),
        ByteField('outer_vxlan_gpe_flags', 0),
        ShortField('reserved2', 0),
        IntField('icmp_header_data', 0),
        IntField('icmpv6_header_data', 0),
        ByteField('icmp_type', 0),
        ByteField('icmp_code', 0),
        ByteField('icmpv6_type', 0),
        ByteField('icmpv6_code', 0),
        IntField('geneve_tlv_option_0_data', 0),
        IntField('gtpu_teid', 0),
        ByteField('gtpu_msg_type', 0),
        BitField('reserved3', 0, 5),
        BitField('gtpu_flags', 0, 3),
        ShortField('reserved4', 0),
        IntField('gtpu_dw_2', 0),
        IntField('gtpu_first_ext_dw_0', 0),
        IntField('gtpu_dw_0', 0),
        StrFixedLenField('reserved5', None, length=4),
    ]


class FlowTableEntryMatchSetLyr24(PRMPacket):
    fields_desc = [
        MACField('smac', '00:00:00:00:00:00'),
        ShortField('ethertype', 0),
        MACField('dmac', '00:00:00:00:00:00'),
        BitField('first_prio', 0, 3),
        BitField('first_cfi', 0, 1),
        BitField('first_vid', 0, 12),
        ByteField('ip_protocol', 0),
        BitField('ip_dscp', 0, 6),
        BitField('ip_ecn', 0, 2),
        BitField('cvlan_tag', 0, 1),
        BitField('svlan_tag', 0, 1),
        BitField('frag', 0, 1),
        BitField('ip_version', 0, 4),
        BitField('tcp_flags', 0, 9),
        ShortField('tcp_sport', 0),
        ShortField('tcp_dport', 0),
        BitField('reserved1', 0, 16),
        BitField('ipv4_ihl', 0, 4),
        BitField('l3_ok', 0, 1),
        BitField('l4_ok', 0, 1),
        BitField('ipv4_checksum_ok', 0, 1),
        BitField('l4_checksum_ok', 0, 1),
        ByteField('ip_ttl_hoplimit', 0),
        ShortField('udp_sport', 0),
        ShortField('udp_dport', 0),
        # Ipv4 and IPv6 fields are edited manually:
        # Added lambda conditioning
        # Field names must be different
        ConditionalField(BitField('src_ip_mask', 0, 128),
                        lambda pkt: pkt.ip_version != 4 and pkt.ip_version != 6),
        ConditionalField(BitField('reserved2', 0, 96),
                         lambda pkt: pkt.ip_version == 4),
        ConditionalField(IPField("src_ip4", "0.0.0.0"),
                         lambda pkt: pkt.ip_version == 4),
        ConditionalField(IP6Field("src_ip6", "::"),
                         lambda pkt: pkt.ip_version == 6),
        ConditionalField(BitField('dst_ip_mask', 0, 128),
                        lambda pkt: pkt.ip_version != 4 and pkt.ip_version != 6),
        ConditionalField(BitField('reserved3', 0, 96),
                         lambda pkt: pkt.ip_version == 4),
        ConditionalField(IPField("dst_ip4", "0.0.0.0"),
                         lambda pkt: pkt.ip_version == 4),
        ConditionalField(IP6Field("dst_ip6", "::"),
                         lambda pkt: pkt.ip_version == 6),
    ]


class ProgSampleField(PRMPacket):
    fields_desc = [
        IntField('prog_sample_field_value', 0),
        IntField('prog_sample_field_id', 0),
    ]


class FlowTableEntryMatchSetMisc4(PRMPacket):
    fields_desc = [
        PacketListField('prog_sample_field', [ProgSampleField() for x in range(4)], ProgSampleField, count_from=lambda pkt:4),
        StrFixedLenField('reserved1', None, length=32),
    ]


class FlowTableEntryMatchSetMisc5(PRMPacket):
    fields_desc = [
        IntField('macsec_tag_0', 0),
        IntField('macsec_tag_1', 0),
        IntField('macsec_tag_2', 0),
        IntField('macsec_tag_3', 0),
        IntField('tunnel_header_0', 0),
        IntField('tunnel_header_1', 0),
        IntField('tunnel_header_2', 0),
        IntField('tunnel_header_3', 0),
        StrFixedLenField('reserved1', None, length=32),
    ]


class FlowTableEntryMatchParam(PRMPacket):
    fields_desc = [
        PacketField('outer_headers', FlowTableEntryMatchSetLyr24(), FlowTableEntryMatchSetLyr24),
        PacketField('misc_parameters', FlowTableEntryMatchSetMisc(), FlowTableEntryMatchSetMisc),
        PacketField('inner_headers', FlowTableEntryMatchSetLyr24(), FlowTableEntryMatchSetLyr24),
        PacketField('misc_parameters_2', FlowTableEntryMatchSetMisc2(), FlowTableEntryMatchSetMisc2),
        PacketField('misc_parameters_3', FlowTableEntryMatchSetMisc3(), FlowTableEntryMatchSetMisc3),
        PacketField('misc_parameters_4', FlowTableEntryMatchSetMisc4(), FlowTableEntryMatchSetMisc4),
        PacketField('misc_parameters_5', FlowTableEntryMatchSetMisc5(), FlowTableEntryMatchSetMisc5),
        # Keep reserved commented out since SW steering checks the size with
        # supported fields only.
        # StrFixedLenField('reserved1', None, length=128),
    ]


class SetActionIn(PRMPacket):
    fields_desc = [
        BitField('action_type', ActionType.SET_ACTION, 4),
        BitField('field', 0, 12),
        BitField('reserved1', 0, 3),
        BitField('offset', 0, 5),
        BitField('reserved2', 0, 3),
        BitField('length', 0, 5),
        IntField('data', 0),
    ]


class CopyActionIn(PRMPacket):
    fields_desc = [
        BitField('action_type', ActionType.COPY_ACTION, 4),
        BitField('src_field', 0, 12),
        BitField('reserved1', 0, 3),
        BitField('src_offset', 0, 5),
        BitField('reserved2', 0, 3),
        BitField('length', 0, 5),
        BitField('reserved3', 0, 4),
        BitField('dst_field', 0, 12),
        BitField('reserved4', 0, 3),
        BitField('dst_offest', 0, 5),
        ByteField('reserved5', 0),
    ]


class AllocFlowCounterIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_ALLOC_FLOW_COUNTER),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        IntField('flow_counter_id', 0),
        BitField('reserved2', 0, 24),
        ByteField('flow_counter_bulk', 0),
    ]


class AllocFlowCounterOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        IntField('flow_counter_id', 0),
        StrFixedLenField('reserved2', None, length=4),
    ]


class DeallocFlowCounterIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_DEALLOC_FLOW_COUNTER),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        IntField('flow_counter_id', 0),
        StrFixedLenField('reserved2', None, length=4),
    ]


class DeallocFlowCounterOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
    ]


class QueryFlowCounterIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_QUERY_FLOW_COUNTER),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        StrFixedLenField('reserved2', None, length=4),
        IntField('mkey', 0),
        LongField('address', 0),
        BitField('clear', 0, 1),
        BitField('dump_to_memory', 0, 1),
        BitField('num_of_counters', 0, 30),
        IntField('flow_counter_id', 0),
    ]


class TrafficCounter(PRMPacket):
    fields_desc = [
        LongField('packets', 0),
        LongField('octets', 0),
    ]


class QueryFlowCounterOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        PacketField('flow_statistics', TrafficCounter(), TrafficCounter),
    ]


class RxHashFieldSelect(PRMPacket):
    fields_desc = [
        BitField('l3_prot_type', 0, 1),
        BitField('l4_prot_type', 0, 1),
        BitField('selected_fields', 0, 30),
    ]


class Tirc(PRMPacket):
    fields_desc = [
        StrFixedLenField('reserved1', None, length=4),
        BitField('disp_type', 0, 4),
        BitField('tls_en', 0, 1),
        BitField('nvmeotcp_zerocopy_en', 0, 1),
        BitField('nvmeotcp_crc_en', 0, 1),
        BitField('reserved2', 0, 25),
        StrFixedLenField('reserved3', None, length=8),
        BitField('reserved4', 0, 4),
        BitField('lro_timeout_period_usecs', 0, 16),
        BitField('lro_enable_mask', 0, 4),
        ByteField('lro_max_msg_sz', 0),
        ByteField('reserved5', 0),
        BitField('afu_id', 0, 24),
        BitField('inline_rqn_vhca_id_valid', 0, 1),
        BitField('reserved6', 0, 15),
        ShortField('inline_rqn_vhca_id', 0),
        BitField('reserved7', 0, 5),
        BitField('inline_q_type', 0, 3),
        BitField('inline_rqn', 0, 24),
        BitField('rx_hash_symmetric', 0, 1),
        BitField('reserved8', 0, 1),
        BitField('tunneled_offload_en', 0, 1),
        BitField('reserved9', 0, 5),
        BitField('indirect_table', 0, 24),
        BitField('rx_hash_fn', 0, 4),
        BitField('reserved10', 0, 2),
        BitField('self_lb_en', 0, 2),
        BitField('transport_domain', 0, 24),
        FieldListField('rx_hash_toeplitz_key', [0 for x in range(10)], IntField('', 0), count_from=lambda pkt:10),
        PacketField('rx_hash_field_selector_outer', RxHashFieldSelect(), RxHashFieldSelect),
        PacketField('rx_hash_field_selector_inner', RxHashFieldSelect(), RxHashFieldSelect),
        IntField('nvmeotcp_tag_buffer_table_id', 0),
        StrFixedLenField('reserved11', None, length=148),
    ]


class CreateTirIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_CREATE_TIR),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        StrFixedLenField('reserved2', None, length=24),
        PacketField('tir_context', Tirc(), Tirc),
    ]


class CreateTirOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('icm_address_63_40', 0, 24),
        IntField('syndrome', 0),
        ByteField('icm_address_39_32', 0),
        BitField('tirn', 0, 24),
        IntField('icm_address_31_0', 0),
    ]


class SwMkc(PRMPacket):
    fields_desc = [
        BitField('reserved1', 0, 1),
        BitField('free', 0, 1),
        BitField('reserved2', 0, 1),
        BitField('access_mode_4_2', 0, 3),
        BitField('alter_pd_to_vhca_id', 0, 1),
        BitField('crossed_side_mkey', 0, 1),
        BitField('reserved3', 0, 5),
        BitField('relaxed_ordering_write', 0, 1),
        BitField('reserved4', 0, 1),
        BitField('small_fence_on_rdma_read_response', 0, 1),
        BitField('umr_en', 0, 1),
        BitField('a', 0, 1),
        BitField('rw', 0, 1),
        BitField('rr', 0, 1),
        BitField('lw', 0, 1),
        BitField('lr', 0, 1),
        BitField('access_mode_1_0', 0, 2),
        BitField('reserved5', 0, 1),
        BitField('tunneled_atomic', 0, 1),
        BitField('ma_translation_mode', 0, 2),
        BitField('reserved6', 0, 4),
        BitField('qpn', 0, 24),
        ByteField('mkey_7_0', 0),
        ByteField('reserved7', 0),
        BitField('pasid', 0, 24),
        BitField('length64', 0, 1),
        BitField('bsf_en', 0, 1),
        BitField('sync_umr', 0, 1),
        BitField('reserved8', 0, 2),
        BitField('expected_sigerr_count', 0, 1),
        BitField('reserved9', 0, 1),
        BitField('en_rinval', 0, 1),
        BitField('pd', 0, 24),
        LongField('start_addr', 0),
        LongField('len', 0),
        IntField('bsf_octword_size', 0),
        StrFixedLenField('reserved10', None, length=12),
        ShortField('crossing_target_vhca_id', 0),
        ShortField('reserved11', 0),
        IntField('translations_octword_size', 0),
        BitField('reserved12', 0, 25),
        BitField('relaxed_ordering_read', 0, 1),
        BitField('reserved13', 0, 1),
        BitField('log_entity_size', 0, 5),
        BitField('reserved14', 0, 3),
        BitField('crypto_en', 0, 2),
        BitField('reserved15', 0, 27),
    ]


class CreateMkeyIn(PRMPacket):
    fields_desc = [
        ShortField('opcode', DevxOps.MLX5_CMD_OP_CREATE_MKEY),
        ShortField('uid', 0),
        ShortField('reserved1', 0),
        ShortField('op_mod', 0),
        ByteField('reserved2', 0),
        BitField('input_mkey_index', 0, 24),
        BitField('pg_access', 0, 1),
        BitField('mkey_umem_valid', 0, 1),
        BitField('reserved3', 0, 30),
        PacketField('sw_mkc', SwMkc(), SwMkc),
        LongField('e_mtt_pointer', 0),
        LongField('e_bsf_pointer', 0),
        IntField('translations_octword_actual_size', 0),
        IntField('mkey_umem_id', 0),
        LongField('mkey_umem_offset', 0),
        IntField('bsf_octword_actual_size', 0),
        StrFixedLenField('reserved4', None, length=156),
        FieldListField('klm_pas_mtt', [0 for x in range(0)], IntField('', 0), count_from=lambda pkt:0),
    ]


class CreateMkeyOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        ByteField('reserved2', 0),
        BitField('mkey_index', 0, 24),
        StrFixedLenField('reserved3', None, length=4),
    ]


class MigrationTagVersion0(PRMPacket):
    fields_desc = [
        ShortField('reserved1', 0),
        ShortField('device_id', 0),
        ShortField('fw_version_minor', 0),
        ShortField('icm_version', 0),
        StrFixedLenField('reserved2', None, length=4),
        IntField('crc', 0),
    ]


class CmdHcaCap2(PRMPacket):
    fields_desc = [
        StrFixedLenField('reserved1', None, length=16),
        BitField('migratable', 0, 1),
        BitField('force_multi_prio_sq', 0, 1),
        BitField('cq_with_emulated_dev_eq', 0, 1),
        BitField('max_num_prog_sample_field', 0, 5),
        BitField('multi_path_force', 0, 1),
        BitField('fw_cpu_monitoring', 0, 1),
        BitField('enh_eth_striding_wq', 0, 1),
        BitField('log_max_num_reserved_qpn', 0, 5),
        BitField('reserved2', 0, 1),
        BitField('introspection_mkey_access_allowed', 0, 1),
        BitField('query_vuid', 0, 1),
        BitField('log_reserved_qpn_granularity', 0, 5),
        BitField('reserved3', 0, 3),
        BitField('log_reserved_qpn_max_alloc', 0, 5),
        ByteField('max_reformat_insert_size', 0),
        ByteField('max_reformat_insert_offset', 0),
        ByteField('max_reformat_remove_size', 0),
        ByteField('max_reformat_remove_offset', 0),
        BitField('multi_sl_qp', 0, 1),
        BitField('non_tunnel_reformat', 0, 1),
        BitField('reserved4', 0, 2),
        BitField('log_min_stride_wqe_sz', 0, 4),
        BitField('migration_multi_load', 0, 1),
        BitField('migration_tracking_state', 0, 1),
        BitField('reserved5', 0, 1),
        BitField('log_conn_track_granularity', 0, 5),
        BitField('reserved6', 0, 3),
        BitField('log_conn_track_max_alloc', 0, 5),
        BitField('reserved7', 0, 3),
        BitField('log_max_conn_track_offload', 0, 5),
        IntField('cross_vhca_object_to_object_supported', 0),
        LongField('allowed_object_for_other_vhca_access', 0),
        IntField('introspection_mkey', 0),
        BitField('ec_mmo_qp', 0, 1),
        BitField('sync_driver_version', 0, 1),
        BitField('driver_version_change_event', 0, 1),
        BitField('hairpin_sq_wqe_bb_size', 0, 5),
        BitField('hairpin_sq_wq_in_host_mem', 0, 1),
        BitField('hairpin_data_buffer_locked', 0, 1),
        BitField('reserved8', 0, 1),
        BitField('log_ec_mmo_max_size', 0, 5),
        BitField('reserved9', 0, 3),
        BitField('log_ec_mmo_max_src', 0, 5),
        BitField('reserved10', 0, 3),
        BitField('log_ec_mmo_max_dst', 0, 5),
        IntField('sync_driver_actions', 0),
        ByteField('flow_table_type_2_type', 0),
        BitField('reserved11', 0, 2),
        BitField('format_select_dw_8_6_ext', 0, 1),
        BitField('reserved12', 0, 1),
        BitField('log_min_mkey_entity_size', 0, 4),
        ShortField('execute_aso_type', 0),
        LongField('general_obj_types_127_64', 0),
        IntField('repeated_mkey_v2', 0),
        BitField('reserved_gid_index_valid', 0, 1),
        BitField('sw_vhca_id_valid', 0, 1),
        BitField('sw_vhca_id', 0, 14),
        ShortField('reserved_gid_index', 0),
        BitField('reserved13', 0, 3),
        BitField('log_max_channel_service_connection', 0, 5),
        BitField('reserved14', 0, 3),
        BitField('ts_cqe_metadata_size2wqe_counter', 0, 5),
        BitField('reserved15', 0, 3),
        BitField('flow_counter_bulk_log_max_alloc', 0, 5),
        BitField('reserved16', 0, 3),
        BitField('flow_counter_bulk_log_granularity', 0, 5),
        ByteField('format_select_dw_mpls_over_x_cw', 0),
        ByteField('format_select_dw_geneve_tlv_option_0', 0),
        ByteField('format_select_dw_outer_first_mpls_over_gre', 0),
        ByteField('format_select_dw_outer_first_mpls_over_udp', 0),
        ByteField('format_select_dw_gtpu_dw_0', 0),
        ByteField('format_select_dw_gtpu_dw_1', 0),
        ByteField('format_select_dw_gtpu_dw_2', 0),
        ByteField('format_select_dw_gtpu_first_ext_dw_0', 0),
        IntField('generate_wqe_type', 0),
        ShortField('max_enh_strwq_supported_profile', 0),
        BitField('reserved17', 0, 3),
        BitField('log_max_total_hairpin_data_buffer_locked_size', 0, 5),
        BitField('reserved18', 0, 3),
        BitField('log_max_rq_hairpin_data_buffer_locked_size', 0, 5),
        BitField('send_dbr_mode_no_dbr_int', 0, 1),
        BitField('send_dbr_mode_no_dbr_ext', 0, 1),
        BitField('reserved19', 0, 1),
        BitField('log_max_send_dbr_less_qp_sq', 0, 5),
        BitField('reserved20', 0, 3),
        BitField('enh_strwq_max_log_page_size', 0, 5),
        ByteField('enh_strwq_max_headroom', 0),
        ByteField('enh_strwq_max_tailroom', 0),
        PacketField('migration_tag_version_0', MigrationTagVersion0(), MigrationTagVersion0),
        BitField('reserved21', 0, 3),
        BitField('log_max_hairpin_wqe_num', 0, 5),
        BitField('reserved22', 0, 24),
        StrFixedLenField('reserved23', None, length=140),
    ]


class QueryCmdHcaCap2Out(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        PadField(PacketField('capability', CmdHcaCap2(), CmdHcaCap2), 2048, padwith=b"\x00"),
    ]


class FlowMeterParams(PRMPacket):
    fields_desc = [
        BitField('valid', 0, 1),
        BitField('bucket_overflow', 0, 1),
        BitField('start_color', 0, 2),
        BitField('both_buckets_on_green', 0, 1),
        BitField('reserved1', 0, 1),
        BitField('meter_mode', 0, 2),
        BitField('reserved2', 0, 24),
        StrFixedLenField('reserved3', None, length=4),
        ByteField('cbs_exponent', 0),
        ByteField('cbs_mantissa', 0),
        BitField('reserved4', 0, 3),
        BitField('cir_exponent', 0, 5),
        ByteField('cir_mantissa', 0),
        StrFixedLenField('reserved5', None, length=4),
        ByteField('ebs_exponent', 0),
        ByteField('ebs_mantissa', 0),
        BitField('reserved6', 0, 3),
        BitField('eir_exponent', 0, 5),
        ByteField('eir_mantissa', 0),
        StrFixedLenField('reserved7', None, length=12),
    ]


class QosCaps(PRMPacket):
    fields_desc = [
        BitField('packet_pacing', 0, 1),
        BitField('esw_scheduling', 0, 1),
        BitField('esw_bw_share', 0, 1),
        BitField('esw_rate_limit', 0, 1),
        BitField('hll', 0, 1),
        BitField('packet_pacing_burst_bound', 0, 1),
        BitField('packet_pacing_typical_size', 0, 1),
        BitField('flow_meter_old', 0, 1),
        BitField('nic_sq_scheduling', 0, 1),
        BitField('nic_bw_share', 0, 1),
        BitField('nic_rate_limit', 0, 1),
        BitField('packet_pacing_uid', 0, 1),
        BitField('log_esw_max_sched_depth', 0, 4),
        ByteField('log_max_flow_meter', 0),
        ByteField('flow_meter_reg_id', 0),
        BitField('wqe_rate_pp', 0, 1),
        BitField('nic_qp_scheduling', 0, 1),
        BitField('reserved1', 0, 2),
        BitField('log_nic_max_sched_depth', 0, 4),
        BitField('flow_meter', 0, 1),
        BitField('reserved2', 0, 1),
        BitField('qos_remap_pp', 0, 1),
        BitField('log_max_qos_nic_queue_group', 0, 5),
        ShortField('reserved3', 0),
        IntField('packet_pacing_max_rate', 0),
        IntField('packet_pacing_min_rate', 0),
        BitField('reserved4', 0, 11),
        BitField('log_esw_max_rate_limit', 0, 5),
        ShortField('packet_pacing_rate_table_size', 0),
        ShortField('esw_element_type', 0),
        ShortField('esw_tsar_type', 0),
        ShortField('max_qos_para_vport', 0),
        ShortField('max_qos_para_vport_old', 0),
        IntField('max_tsar_bw_share', 0),
        ShortField('nic_element_type', 0),
        ShortField('nic_tsar_type', 0),
        BitField('reserved5', 0, 3),
        BitField('log_meter_aso_granularity', 0, 5),
        BitField('reserved6', 0, 3),
        BitField('log_meter_aso_max_alloc', 0, 5),
        BitField('reserved7', 0, 3),
        BitField('log_max_num_meter_aso', 0, 5),
        ByteField('reserved8', 0),
        BitField('reserved9', 0, 3),
        BitField('log_max_qos_nic_scheduling_element', 0, 5),
        BitField('reserved10', 0, 3),
        BitField('log_max_qos_esw_scheduling_element', 0, 5),
        ShortField('reserved11', 0),
        StrFixedLenField('reserved12', None, length=212),
    ]


class QueryQosCapOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        PadField(PacketField('capability', QosCaps(), QosCaps), 4096, padwith=b"\x00"),
    ]


class FlowTableFieldsSupported2(PRMPacket):
    fields_desc = [
        BitField('reserved1', 0, 10),
        BitField('lag_rx_port_affinity', 0, 1),
        BitField('inner_esp_seq_num', 0, 1),
        BitField('outer_esp_seq_num', 0, 1),
        BitField('hash_result', 0, 1),
        BitField('bth_opcode', 0, 1),
        BitField('tunnel_header_2_3', 0, 1),
        BitField('tunnel_header_0_1', 0, 1),
        BitField('macsec_syndrome', 0, 1),
        BitField('macsec_tag', 0, 1),
        BitField('outer_lrh_sl', 0, 1),
        BitField('inner_ipv4_ihl', 0, 1),
        BitField('outer_ipv4_ihl', 0, 1),
        BitField('nisp_syndrome', 0, 1),
        BitField('inner_l3_ok', 0, 1),
        BitField('inner_l4_ok', 0, 1),
        BitField('outer_l3_ok', 0, 1),
        BitField('outer_l4_ok', 0, 1),
        BitField('nisp_header', 0, 1),
        BitField('inner_ipv4_checksum_ok', 0, 1),
        BitField('inner_l4_checksum_ok', 0, 1),
        BitField('outer_ipv4_checksum_ok', 0, 1),
        BitField('outer_l4_checksum_ok', 0, 1),
        StrFixedLenField('reserved2', None, length=12),
    ]


class FlowTableFieldsSupported(PRMPacket):
    fields_desc = [
        BitField('outer_dmac', 0, 1),
        BitField('outer_smac', 0, 1),
        BitField('outer_ether_type', 0, 1),
        BitField('outer_ip_version', 0, 1),
        BitField('outer_first_prio', 0, 1),
        BitField('outer_first_cfi', 0, 1),
        BitField('outer_first_vid', 0, 1),
        BitField('outer_ipv4_ttl', 0, 1),
        BitField('outer_second_prio', 0, 1),
        BitField('outer_second_cfi', 0, 1),
        BitField('outer_second_vid', 0, 1),
        BitField('outer_ipv6_flow_label', 0, 1),
        BitField('outer_sip', 0, 1),
        BitField('outer_dip', 0, 1),
        BitField('outer_frag', 0, 1),
        BitField('outer_ip_protocol', 0, 1),
        BitField('outer_ip_ecn', 0, 1),
        BitField('outer_ip_dscp', 0, 1),
        BitField('outer_udp_sport', 0, 1),
        BitField('outer_udp_dport', 0, 1),
        BitField('outer_tcp_sport', 0, 1),
        BitField('outer_tcp_dport', 0, 1),
        BitField('outer_tcp_flags', 0, 1),
        BitField('outer_gre_protocol', 0, 1),
        BitField('outer_gre_key', 0, 1),
        BitField('outer_vxlan_vni', 0, 1),
        BitField('outer_geneve_vni', 0, 1),
        BitField('outer_geneve_oam', 0, 1),
        BitField('outer_geneve_protocol_type', 0, 1),
        BitField('outer_geneve_opt_len', 0, 1),
        BitField('source_vhca_port', 0, 1),
        BitField('source_eswitch_port', 0, 1),
        BitField('inner_dmac', 0, 1),
        BitField('inner_smac', 0, 1),
        BitField('inner_ether_type', 0, 1),
        BitField('inner_ip_version', 0, 1),
        BitField('inner_first_prio', 0, 1),
        BitField('inner_first_cfi', 0, 1),
        BitField('inner_first_vid', 0, 1),
        BitField('inner_ipv4_ttl', 0, 1),
        BitField('inner_second_prio', 0, 1),
        BitField('inner_second_cfi', 0, 1),
        BitField('inner_second_vid', 0, 1),
        BitField('inner_ipv6_flow_label', 0, 1),
        BitField('inner_sip', 0, 1),
        BitField('inner_dip', 0, 1),
        BitField('inner_frag', 0, 1),
        BitField('inner_ip_protocol', 0, 1),
        BitField('inner_ip_ecn', 0, 1),
        BitField('inner_ip_dscp', 0, 1),
        BitField('inner_udp_sport', 0, 1),
        BitField('inner_udp_dport', 0, 1),
        BitField('inner_tcp_sport', 0, 1),
        BitField('inner_tcp_dport', 0, 1),
        BitField('inner_tcp_flags', 0, 1),
        BitField('outer_tcp_seq_num', 0, 1),
        BitField('inner_tcp_seq_num', 0, 1),
        BitField('prog_sample_field', 0, 1),
        BitField('outer_first_mpls_over_udp_cw', 0, 1),
        BitField('outer_tcp_ack_num', 0, 1),
        BitField('inner_tcp_ack_num', 0, 1),
        BitField('outer_first_mpls_over_gre_cw', 0, 1),
        BitField('metadata_reg_b', 0, 1),
        BitField('metadata_reg_a', 0, 1),
        BitField('geneve_tlv_option_0_data', 0, 1),
        BitField('geneve_tlv_option_0_exist', 0, 1),
        BitField('outer_vxlan_gpe_vni', 0, 1),
        BitField('outer_vxlan_gpe_flags', 0, 1),
        BitField('outer_vxlan_gpe_next_protocol', 0, 1),
        BitField('outer_first_mpls_over_gre_ttl', 0, 1),
        BitField('outer_first_mpls_over_gre_s_bos', 0, 1),
        BitField('outer_first_mpls_over_gre_exp', 0, 1),
        BitField('outer_first_mpls_over_gre_label', 0, 1),
        BitField('outer_first_mpls_over_udp_ttl', 0, 1),
        BitField('outer_first_mpls_over_udp_s_bos', 0, 1),
        BitField('outer_first_mpls_over_udp_exp', 0, 1),
        BitField('outer_first_mpls_over_udp_label', 0, 1),
        BitField('inner_first_mpls_ttl', 0, 1),
        BitField('inner_first_mpls_s_bos', 0, 1),
        BitField('inner_first_mpls_exp', 0, 1),
        BitField('inner_first_mpls_label', 0, 1),
        BitField('outer_first_mpls_ttl', 0, 1),
        BitField('outer_first_mpls_s_bos', 0, 1),
        BitField('outer_first_mpls_exp', 0, 1),
        BitField('outer_first_mpls_label', 0, 1),
        BitField('outer_emd_tag', 0, 1),
        BitField('inner_esp_spi', 0, 1),
        BitField('outer_esp_spi', 0, 1),
        BitField('inner_ipv6_hop_limit', 0, 1),
        BitField('outer_ipv6_hop_limit', 0, 1),
        BitField('bth_dst_qp', 0, 1),
        BitField('inner_first_svlan', 0, 1),
        BitField('inner_second_svlan', 0, 1),
        BitField('outer_first_svlan', 0, 1),
        BitField('outer_second_svlan', 0, 1),
        BitField('source_sqn', 0, 1),
        BitField('outer_gre_c_present', 0, 1),
        BitField('outer_gre_k_present', 0, 1),
        BitField('outer_gre_s_present', 0, 1),
        BitField('ipsec_syndrome', 0, 1),
        BitField('ipsec_next_header', 0, 1),
        BitField('gtpu_first_ext_dw_0', 0, 1),
        BitField('gtpu_dw_0', 0, 1),
        BitField('gtpu_teid', 0, 1),
        BitField('gtpu_msg_type', 0, 1),
        BitField('gtpu_flags', 0, 1),
        BitField('outer_lrh_lid', 0, 1),
        BitField('outer_grh_flow_label', 0, 1),
        BitField('outer_grh_tclass', 0, 1),
        BitField('outer_grh_gid', 0, 1),
        BitField('outer_bth_pkey', 0, 1),
        BitField('gtpu_dw_2', 0, 1),
        BitField('reserved1', 0, 2),
        BitField('icmpv6_code', 0, 1),
        BitField('icmp_code', 0, 1),
        BitField('icmpv6_type', 0, 1),
        BitField('icmp_type', 0, 1),
        BitField('icmpv6_header_data', 0, 1),
        BitField('icmp_header_data', 0, 1),
        BitField('metadata_reg_c_7', 0, 1),
        BitField('metadata_reg_c_6', 0, 1),
        BitField('metadata_reg_c_5', 0, 1),
        BitField('metadata_reg_c_4', 0, 1),
        BitField('metadata_reg_c_3', 0, 1),
        BitField('metadata_reg_c_2', 0, 1),
        BitField('metadata_reg_c_1', 0, 1),
        BitField('metadata_reg_c_0', 0, 1),
    ]


class HeaderModifyCapProperties(PRMPacket):
    fields_desc = [
        PacketField('set_action_field_support', FlowTableFieldsSupported(),
                    FlowTableFieldsSupported),
        PacketField('set_action_field_support_2', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('add_action_field_support', FlowTableFieldsSupported(),
                    FlowTableFieldsSupported),
        PacketField('add_action_field_support_2', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('copy_action_field_support', FlowTableFieldsSupported(),
                    FlowTableFieldsSupported),
        PacketField('copy_action_field_support_2', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        StrFixedLenField('reserved1', None, length=32),
    ]


class FlowTablePropLayout(PRMPacket):
    fields_desc = [
        BitField('ft_support', 0, 1),
        BitField('flow_tag', 0, 1),
        BitField('flow_counter', 0, 1),
        BitField('flow_modify_en', 0, 1),
        BitField('modify_root', 0, 1),
        BitField('identified_miss_table', 0, 1),
        BitField('flow_table_modify', 0, 1),
        BitField('reformat', 0, 1),
        BitField('decap', 0, 1),
        BitField('reset_root_to_default', 0, 1),
        BitField('pop_vlan', 0, 1),
        BitField('push_vlan', 0, 1),
        BitField('fpga_vendor_acceleration', 0, 1),
        BitField('pop_vlan_2', 0, 1),
        BitField('push_vlan_2', 0, 1),
        BitField('reformat_and_vlan_action', 0, 1),
        BitField('modify_and_vlan_action', 0, 1),
        BitField('sw_owner', 0, 1),
        BitField('reformat_l3_tunnel_to_l2', 0, 1),
        BitField('reformat_l2_to_l3_tunnel', 0, 1),
        BitField('reformat_and_modify_action', 0, 1),
        BitField('ignore_flow_level', 0, 1),
        BitField('reserved1', 0, 1),
        BitField('table_miss_action_domain', 0, 1),
        BitField('termination_table', 0, 1),
        BitField('reformat_and_fwd_to_table', 0, 1),
        BitField('forward_vhca_rx_root', 0, 1),
        BitField('forward_vhca_tx_root', 0, 1),
        BitField('ipsec_encrypt', 0, 1),
        BitField('ipsec_decrypt', 0, 1),
        BitField('sw_owner_v2', 0, 1),
        BitField('wqe_based_flow_update', 0, 1),
        BitField('termination_table_raw_traffic', 0, 1),
        BitField('vlan_and_fwd_to_table', 0, 1),
        BitField('log_max_ft_size', 0, 6),
        ByteField('log_max_modify_header_context', 0),
        ByteField('max_modify_header_actions', 0),
        ByteField('max_ft_level', 0),
        BitField('reformat_add_esp_transport', 0, 1),
        BitField('reformat_l2_to_l3_esp_tunnel', 0, 1),
        BitField('reformat_add_esp_transport_over_udp', 0, 1),
        BitField('reformat_del_esp_transport', 0, 1),
        BitField('reformat_l3_esp_tunnel_to_l2', 0, 1),
        BitField('reformat_del_esp_transport_over_udp', 0, 1),
        BitField('execute_aso', 0, 1),
        BitField('forward_flow_meter', 0, 1),
        ByteField('log_max_flow_sampler_num', 0),
        ByteField('metadata_reg_b_width', 0),
        ByteField('metadata_reg_a_width', 0),
        BitField('reformat_l2_to_l3_nisp_tunnel', 0, 1),
        BitField('reformat_l3_nisp_tunnel_to_l2', 0, 1),
        BitField('reformat_insert', 0, 1),
        BitField('reformat_remove', 0, 1),
        BitField('macsec_encrypt', 0, 1),
        BitField('macsec_decrypt', 0, 1),
        BitField('nisp_encrypt', 0, 1),
        BitField('nisp_decrypt', 0, 1),
        BitField('reformat_add_macsec', 0, 1),
        BitField('reformat_remove_macsec', 0, 1),
        BitField('reparse', 0, 1),
        BitField('reserved2', 0, 1),
        BitField('cross_vhca_object', 0, 1),
        BitField('reserved3', 0, 11),
        ByteField('log_max_ft_num', 0),
        ShortField('reserved4', 0),
        ByteField('log_max_flow_counter', 0),
        ByteField('log_max_destination', 0),
        BitField('reserved5', 0, 24),
        ByteField('log_max_flow', 0),
        StrFixedLenField('reserved6', None, length=8),
        PacketField('ft_field_support', FlowTableFieldsSupported(), FlowTableFieldsSupported),
        PacketField('ft_field_bitmask_support', FlowTableFieldsSupported(),
                    FlowTableFieldsSupported),
    ]


class FlowTableNicCap(PRMPacket):
    fields_desc = [
        BitField('nic_rx_multi_path_tirs', 0, 1),
        BitField('nic_rx_multi_path_tirs_fts', 0, 1),
        BitField('allow_sniffer_and_nic_rx_shared_tir', 0, 1),
        BitField('reserved1', 0, 1),
        BitField('nic_rx_flow_tag_multipath_en', 0, 1),
        BitField('ttl_checksum_correction', 0, 1),
        BitField('nic_rx_rdma_fwd_tir', 0, 1),
        BitField('sw_owner_reformat_supported', 0, 1),
        ShortField('reserved2', 0),
        ByteField('nic_receive_max_steering_depth', 0),
        BitField('encap_general_header', 0, 1),
        BitField('reserved3', 0, 10),
        BitField('log_max_packet_reformat_context', 0, 5),
        BitField('reserved4', 0, 6),
        BitField('max_encap_header_size', 0, 10),
        StrFixedLenField('reserved5', None, length=56),
        PacketField('flow_table_properties_nic_receive', FlowTablePropLayout(),
                    FlowTablePropLayout),
        PacketField('flow_table_properties_nic_receive_rdma', FlowTablePropLayout(),
                    FlowTablePropLayout),
        PacketField('flow_table_properties_nic_receive_sniffer', FlowTablePropLayout(),
                    FlowTablePropLayout),
        PacketField('flow_table_properties_nic_transmit', FlowTablePropLayout(),
                    FlowTablePropLayout),
        PacketField('flow_table_properties_nic_transmit_rdma', FlowTablePropLayout(),
                    FlowTablePropLayout),
        PacketField('flow_table_properties_nic_transmit_sniffer', FlowTablePropLayout(),
                    FlowTablePropLayout),
        StrFixedLenField('reserved6', None, length=64),
        PacketField('header_modify_nic_receive', HeaderModifyCapProperties(),
                    HeaderModifyCapProperties),
        PacketField('ft_field_support_2_nic_receive', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_bitmask_support_2_nic_receive', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_support_2_nic_receive_rdma', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_bitmask_support_2_nic_receive_rdma', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_support_2_nic_receive_sniffer', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_bitmask_support_2_nic_receive_sniffer', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_support_2_nic_transmit', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_bitmask_support_2_nic_transmit', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_support_2_nic_transmit_rdma', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_bitmask_support_2_nic_transmit_rdma', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_support_2_nic_transmit_sniffer', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        PacketField('ft_field_bitmask_support_2_nic_transmit_sniffer', FlowTableFieldsSupported2(),
                    FlowTableFieldsSupported2),
        StrFixedLenField('reserved7', None, length=64),
        PacketField('header_modify_nic_transmit', HeaderModifyCapProperties(),
                    HeaderModifyCapProperties),
        LongField('sw_steering_nic_rx_action_drop_icm_address', 0),
        LongField('sw_steering_nic_tx_action_drop_icm_address', 0),
        LongField('sw_steering_nic_tx_action_allow_icm_address', 0),
        StrFixedLenField('reserved8', None, length=40),
    ]


class QueryCmdHcaNicFlowTableCapOut(PRMPacket):
    fields_desc = [
        ByteField('status', 0),
        BitField('reserved1', 0, 24),
        IntField('syndrome', 0),
        StrFixedLenField('reserved2', None, length=8),
        PadField(PacketField('capability', FlowTableNicCap(), FlowTableNicCap), 2048,
                 padwith=b"\x00"),
    ]
