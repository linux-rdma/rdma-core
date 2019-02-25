# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.

cdef extern from '<infiniband/verbs.h>':

    cpdef enum:
        IBV_LINK_LAYER_UNSPECIFIED
        IBV_LINK_LAYER_INFINIBAND
        IBV_LINK_LAYER_ETHERNET

    cpdef enum ibv_atomic_cap:
        IBV_ATOMIC_NONE
        IBV_ATOMIC_HCA
        IBV_ATOMIC_GLOB

    cpdef enum ibv_port_state:
        IBV_PORT_NOP                = 0
        IBV_PORT_DOWN               = 1
        IBV_PORT_INIT               = 2
        IBV_PORT_ARMED              = 3
        IBV_PORT_ACTIVE             = 4
        IBV_PORT_ACTIVE_DEFER       = 5

    cpdef enum ibv_port_cap_flags:
        IBV_PORT_SM                         = 1 <<  1
        IBV_PORT_NOTICE_SUP                 = 1 <<  2
        IBV_PORT_TRAP_SUP                   = 1 <<  3
        IBV_PORT_OPT_IPD_SUP                = 1 <<  4
        IBV_PORT_AUTO_MIGR_SUP              = 1 <<  5
        IBV_PORT_SL_MAP_SUP                 = 1 <<  6
        IBV_PORT_MKEY_NVRAM                 = 1 <<  7
        IBV_PORT_PKEY_NVRAM                 = 1 <<  8
        IBV_PORT_LED_INFO_SUP               = 1 <<  9
        IBV_PORT_SYS_IMAGE_GUID_SUP         = 1 << 11
        IBV_PORT_PKEY_SW_EXT_PORT_TRAP_SUP  = 1 << 12
        IBV_PORT_EXTENDED_SPEEDS_SUP        = 1 << 14
        IBV_PORT_CAP_MASK2_SUP              = 1 << 15,
        IBV_PORT_CM_SUP                     = 1 << 16
        IBV_PORT_SNMP_TUNNEL_SUP            = 1 << 17
        IBV_PORT_REINIT_SUP                 = 1 << 18
        IBV_PORT_DEVICE_MGMT_SUP            = 1 << 19
        IBV_PORT_VENDOR_CLASS_SUP           = 1 << 20
        IBV_PORT_DR_NOTICE_SUP              = 1 << 21
        IBV_PORT_CAP_MASK_NOTICE_SUP        = 1 << 22
        IBV_PORT_BOOT_MGMT_SUP              = 1 << 23
        IBV_PORT_LINK_LATENCY_SUP           = 1 << 24
        IBV_PORT_CLIENT_REG_SUP             = 1 << 25
        IBV_PORT_IP_BASED_GIDS              = 1 << 26

    cpdef enum ibv_port_cap_flags2:
        IBV_PORT_SET_NODE_DESC_SUP              = 1 << 0
        IBV_PORT_INFO_EXT_SUP                   = 1 << 1
        IBV_PORT_VIRT_SUP                       = 1 << 2
        IBV_PORT_SWITCH_PORT_STATE_TABLE_SUP    = 1 << 3
        IBV_PORT_LINK_WIDTH_2X_SUP              = 1 << 4
        IBV_PORT_LINK_SPEED_HDR_SUP             = 1 << 5

    cpdef enum ibv_mtu:
        IBV_MTU_256     = 1
        IBV_MTU_512     = 2
        IBV_MTU_1024    = 3
        IBV_MTU_2048    = 4
        IBV_MTU_4096    = 5

    cpdef enum ibv_event_type:
        IBV_EVENT_CQ_ERR
        IBV_EVENT_QP_FATAL
        IBV_EVENT_QP_REQ_ERR
        IBV_EVENT_QP_ACCESS_ERR
        IBV_EVENT_COMM_EST
        IBV_EVENT_SQ_DRAINED
        IBV_EVENT_PATH_MIG
        IBV_EVENT_PATH_MIG_ERR
        IBV_EVENT_DEVICE_FATAL
        IBV_EVENT_PORT_ACTIVE
        IBV_EVENT_PORT_ERR
        IBV_EVENT_LID_CHANGE
        IBV_EVENT_PKEY_CHANGE
        IBV_EVENT_SM_CHANGE
        IBV_EVENT_SRQ_ERR
        IBV_EVENT_SRQ_LIMIT_REACHED
        IBV_EVENT_QP_LAST_WQE_REACHED
        IBV_EVENT_CLIENT_REREGISTER
        IBV_EVENT_GID_CHANGE
        IBV_EVENT_WQ_FATAL

    cpdef enum ibv_access_flags:
        IBV_ACCESS_LOCAL_WRITE      = 1
        IBV_ACCESS_REMOTE_WRITE     = (1 << 1)
        IBV_ACCESS_REMOTE_READ      = (1 << 2)
        IBV_ACCESS_REMOTE_ATOMIC    = (1 << 3)
        IBV_ACCESS_MW_BIND          = (1 << 4)
        IBV_ACCESS_ZERO_BASED       = (1 << 5)
        IBV_ACCESS_ON_DEMAND        = (1 << 6)

    cpdef enum ibv_wr_opcode:
        IBV_WR_RDMA_WRITE
        IBV_WR_RDMA_WRITE_WITH_IMM
        IBV_WR_SEND
        IBV_WR_SEND_WITH_IMM
        IBV_WR_RDMA_READ
        IBV_WR_ATOMIC_CMP_AND_SWP
        IBV_WR_ATOMIC_FETCH_AND_ADD
        IBV_WR_LOCAL_INV
        IBV_WR_BIND_MW
        IBV_WR_SEND_WITH_INV
        IBV_WR_TSO

    cpdef enum ibv_send_flags:
        IBV_SEND_FENCE      = 1 << 0
        IBV_SEND_SIGNALED   = 1 << 1
        IBV_SEND_SOLICITED  = 1 << 2
        IBV_SEND_INLINE     = 1 << 3
        IBV_SEND_IP_CSUM    = 1 << 4

    cpdef enum ibv_qp_type:
        IBV_QPT_RC          = 2
        IBV_QPT_UC          = 3
        IBV_QPT_UD          = 4
        IBV_QPT_RAW_PACKET  = 8
        IBV_QPT_XRC_SEND    = 9
        IBV_QPT_XRC_RECV    = 10
        IBV_QPT_DRIVER      = 0xff

    cpdef enum ibv_qp_state:
        IBV_QPS_RESET
        IBV_QPS_INIT
        IBV_QPS_RTR
        IBV_QPS_RTS
        IBV_QPS_SQD
        IBV_QPS_SQE
        IBV_QPS_ERR
        IBV_QPS_UNKNOWN

    cpdef enum ibv_mw_type:
        IBV_MW_TYPE_1   = 1
        IBV_MW_TYPE_2   = 2

    cpdef enum ibv_wc_status:
        IBV_WC_SUCCESS
        IBV_WC_LOC_LEN_ERR
        IBV_WC_LOC_QP_OP_ERR
        IBV_WC_LOC_EEC_OP_ERR
        IBV_WC_LOC_PROT_ERR
        IBV_WC_WR_FLUSH_ERR
        IBV_WC_MW_BIND_ERR
        IBV_WC_BAD_RESP_ERR
        IBV_WC_LOC_ACCESS_ERR
        IBV_WC_REM_INV_REQ_ERR
        IBV_WC_REM_ACCESS_ERR
        IBV_WC_REM_OP_ERR
        IBV_WC_RETRY_EXC_ERR
        IBV_WC_RNR_RETRY_EXC_ERR
        IBV_WC_LOC_RDD_VIOL_ERR
        IBV_WC_REM_INV_RD_REQ_ERR
        IBV_WC_REM_ABORT_ERR
        IBV_WC_INV_EECN_ERR
        IBV_WC_INV_EEC_STATE_ERR
        IBV_WC_FATAL_ERR
        IBV_WC_RESP_TIMEOUT_ERR
        IBV_WC_GENERAL_ERR

    cpdef enum ibv_wc_opcode:
        IBV_WC_SEND
        IBV_WC_RDMA_WRITE
        IBV_WC_RDMA_READ
        IBV_WC_COMP_SWAP
        IBV_WC_FETCH_ADD
        IBV_WC_BIND_MW
        IBV_WC_LOCAL_INV
        IBV_WC_TSO
        IBV_WC_RECV         = 1 << 7
        IBV_WC_RECV_RDMA_WITH_IMM

    cpdef enum ibv_create_cq_wc_flags:
        IBV_WC_EX_WITH_BYTE_LEN                 = 1 << 0
        IBV_WC_EX_WITH_IMM                      = 1 << 1
        IBV_WC_EX_WITH_QP_NUM                   = 1 << 2
        IBV_WC_EX_WITH_SRC_QP                   = 1 << 3
        IBV_WC_EX_WITH_SLID                     = 1 << 4
        IBV_WC_EX_WITH_SL                       = 1 << 5
        IBV_WC_EX_WITH_DLID_PATH_BITS           = 1 << 6
        IBV_WC_EX_WITH_COMPLETION_TIMESTAMP     = 1 << 7
        IBV_WC_EX_WITH_CVLAN                    = 1 << 8
        IBV_WC_EX_WITH_FLOW_TAG                 = 1 << 9
        IBV_WC_EX_WITH_TM_INFO                  = 1 << 10

    cpdef enum ibv_wc_flags:
        IBV_WC_GRH              = 1 << 0
        IBV_WC_WITH_IMM         = 1 << 1
        IBV_WC_IP_CSUM_OK       = 1 << 2
        IBV_WC_WITH_INV         = 1 << 3
        IBV_WC_TM_SYNC_REQ      = 1 << 4
        IBV_WC_TM_MATCH         = 1 << 5
        IBV_WC_TM_DATA_VALID    = 1 << 6

    cpdef enum ibv_tm_cap_flags:
        IBV_TM_CAP_RC       = 1 << 0,

    cpdef enum ibv_srq_attr_mask:
        IBV_SRQ_MAX_WR      = 1 << 0,
        IBV_SRQ_LIMIT       = 1 << 1

    cpdef enum ibv_srq_type:
        IBV_SRQT_BASIC
        IBV_SRQT_XRC
        IBV_SRQT_TM

    cpdef enum ibv_srq_init_attr_mask:
        IBV_SRQ_INIT_ATTR_TYPE      = 1 << 0
        IBV_SRQ_INIT_ATTR_PD        = 1 << 1
        IBV_SRQ_INIT_ATTR_XRCD      = 1 << 2
        IBV_SRQ_INIT_ATTR_CQ        = 1 << 3
        IBV_SRQ_INIT_ATTR_TM        = 1 << 4

    cpdef enum ibv_mig_state:
        IBV_MIG_MIGRATED
        IBV_MIG_REARM
        IBV_MIG_ARMED

    cpdef enum ibv_qp_init_attr_mask:
        IBV_QP_INIT_ATTR_PD             = 1 << 0
        IBV_QP_INIT_ATTR_XRCD           = 1 << 1
        IBV_QP_INIT_ATTR_CREATE_FLAGS   = 1 << 2
        IBV_QP_INIT_ATTR_MAX_TSO_HEADER = 1 << 3
        IBV_QP_INIT_ATTR_IND_TABLE      = 1 << 4
        IBV_QP_INIT_ATTR_RX_HASH        = 1 << 5

    cpdef enum ibv_qp_create_flags:
        IBV_QP_CREATE_BLOCK_SELF_MCAST_LB   = 1 << 1
        IBV_QP_CREATE_SCATTER_FCS           = 1 << 8
        IBV_QP_CREATE_CVLAN_STRIPPING       = 1 << 9
        IBV_QP_CREATE_SOURCE_QPN            = 1 << 10
        IBV_QP_CREATE_PCI_WRITE_END_PADDING = 1 << 11

    cpdef enum ibv_qp_attr_mask:
        IBV_QP_STATE                = 1 << 0
        IBV_QP_CUR_STATE            = 1 << 1
        IBV_QP_EN_SQD_ASYNC_NOTIFY  = 1 << 2
        IBV_QP_ACCESS_FLAGS         = 1 << 3
        IBV_QP_PKEY_INDEX           = 1 << 4
        IBV_QP_PORT                 = 1 << 5
        IBV_QP_QKEY                 = 1 << 6
        IBV_QP_AV                   = 1 << 7
        IBV_QP_PATH_MTU             = 1 << 8
        IBV_QP_TIMEOUT              = 1 << 9
        IBV_QP_RETRY_CNT            = 1 << 10
        IBV_QP_RNR_RETRY            = 1 << 11
        IBV_QP_RQ_PSN               = 1 << 12
        IBV_QP_MAX_QP_RD_ATOMIC     = 1 << 13
        IBV_QP_ALT_PATH             = 1 << 14
        IBV_QP_MIN_RNR_TIMER        = 1 << 15
        IBV_QP_SQ_PSN               = 1 << 16
        IBV_QP_MAX_DEST_RD_ATOMIC   = 1 << 17
        IBV_QP_PATH_MIG_STATE       = 1 << 18
        IBV_QP_CAP                  = 1 << 19
        IBV_QP_DEST_QPN             = 1 << 20
        IBV_QP_RATE_LIMIT           = 1 << 25

    cpdef enum ibv_wq_type:
        IBV_WQT_RQ

    cpdef enum ibv_wq_init_attr_mask:
        IBV_WQ_INIT_ATTR_FLAGS      = 1 << 0

    cpdef enum ibv_wq_flags:
        IBV_WQ_FLAGS_CVLAN_STRIPPING        = 1 << 0
        IBV_WQ_FLAGS_SCATTER_FCS            = 1 << 1
        IBV_WQ_FLAGS_DELAY_DROP             = 1 << 2
        IBV_WQ_FLAGS_PCI_WRITE_END_PADDING  = 1 << 3

    cpdef enum ibv_wq_state:
        IBV_WQS_RESET
        IBV_WQS_RDY
        IBV_WQS_ERR
        IBV_WQS_UNKNOWN

    cpdef enum ibv_wq_attr_mask:
        IBV_WQ_ATTR_STATE       = 1 << 0
        IBV_WQ_ATTR_CURR_STATE  = 1 << 1
        IBV_WQ_ATTR_FLAGS       = 1 << 2

    cpdef enum ibv_rx_hash_function_flags:
        IBV_RX_HASH_FUNC_TOEPLITZ   = 1 << 0

    cpdef enum ibv_rx_hash_fields:
        IBV_RX_HASH_SRC_IPV4        = 1 << 0
        IBV_RX_HASH_DST_IPV4        = 1 << 1
        IBV_RX_HASH_SRC_IPV6        = 1 << 2
        IBV_RX_HASH_DST_IPV6        = 1 << 3
        IBV_RX_HASH_SRC_PORT_TCP    = 1 << 4
        IBV_RX_HASH_DST_PORT_TCP    = 1 << 5
        IBV_RX_HASH_SRC_PORT_UDP    = 1 << 6
        IBV_RX_HASH_DST_PORT_UDP    = 1 << 7

    cpdef enum ibv_ops_wr_opcode:
        IBV_WR_TAG_ADD
        IBV_WR_TAG_DEL
        IBV_WR_TAG_SYNC

    cpdef enum ibv_ops_flags:
        IBV_OPS_SIGNALED            = 1 << 0
        IBV_OPS_TM_SYNC             = 1 << 1

    cpdef enum ibv_flow_flags:
        IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK = 1 << 0
        IBV_FLOW_ATTR_FLAGS_DONT_TRAP       = 1 << 1
        IBV_FLOW_ATTR_FLAGS_EGRESS          = 1 << 2

    cpdef enum ibv_flow_attr_type:
        IBV_FLOW_ATTR_NORMAL      = 0x0
        IBV_FLOW_ATTR_ALL_DEFAULT = 0x1
        IBV_FLOW_ATTR_MC_DEFAULT  = 0x2
        IBV_FLOW_ATTR_SNIFFER     = 0x3

    cpdef enum ibv_flow_spec_type:
        IBV_FLOW_SPEC_ETH           = 0x20
        IBV_FLOW_SPEC_IPV4          = 0x30
        IBV_FLOW_SPEC_IPV6          = 0x31
        IBV_FLOW_SPEC_IPV4_EXT      = 0x32
        IBV_FLOW_SPEC_ESP           = 0x34
        IBV_FLOW_SPEC_TCP           = 0x40
        IBV_FLOW_SPEC_UDP           = 0x41
        IBV_FLOW_SPEC_VXLAN_TUNNEL  = 0x50
        IBV_FLOW_SPEC_GRE           = 0x51
        IBV_FLOW_SPEC_MPLS          = 0x60
        IBV_FLOW_SPEC_INNER         = 0x100
        IBV_FLOW_SPEC_ACTION_TAG    = 0x1000
        IBV_FLOW_SPEC_ACTION_DROP   = 0x1001
        IBV_FLOW_SPEC_ACTION_HANDLE = 0x1002
        IBV_FLOW_SPEC_ACTION_COUNT  = 0x1003

    cpdef enum:
        IBV_QPF_GRH_REQUIRED

    cpdef enum ibv_counter_description:
        IBV_COUNTER_PACKETS
        IBV_COUNTER_BYTES

    cpdef enum ibv_read_counters_flags:
        IBV_READ_COUNTERS_ATTR_PREFER_CACHED = 1 << 0

cdef extern from "<infiniband/tm_types.h>":
    cpdef enum ibv_tmh_op:
        IBV_TMH_NO_TAG        = 0
        IBV_TMH_RNDV          = 1
        IBV_TMH_FIN           = 2
        IBV_TMH_EAGER         = 3
