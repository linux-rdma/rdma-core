# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.

#cython: language_level=3


cdef extern from '<infiniband/verbs.h>':

    cpdef enum ibv_transport_type:
        IBV_TRANSPORT_UNKNOWN
        IBV_TRANSPORT_IB
        IBV_TRANSPORT_IWARP
        IBV_TRANSPORT_USNIC
        IBV_TRANSPORT_USNIC_UDP

    cpdef enum ibv_node_type:
        IBV_NODE_UNKNOWN
        IBV_NODE_CA
        IBV_NODE_SWITCH
        IBV_NODE_ROUTER
        IBV_NODE_RNIC
        IBV_NODE_USNIC
        IBV_NODE_USNIC_UDP

    cpdef enum:
        IBV_LINK_LAYER_UNSPECIFIED
        IBV_LINK_LAYER_INFINIBAND
        IBV_LINK_LAYER_ETHERNET

    cpdef enum ibv_atomic_cap:
        IBV_ATOMIC_NONE
        IBV_ATOMIC_HCA
        IBV_ATOMIC_GLOB

    cpdef enum ibv_port_state:
        IBV_PORT_NOP
        IBV_PORT_DOWN
        IBV_PORT_INIT
        IBV_PORT_ARMED
        IBV_PORT_ACTIVE
        IBV_PORT_ACTIVE_DEFER

    cpdef enum ibv_port_cap_flags:
        IBV_PORT_SM
        IBV_PORT_NOTICE_SUP
        IBV_PORT_TRAP_SUP
        IBV_PORT_OPT_IPD_SUP
        IBV_PORT_AUTO_MIGR_SUP
        IBV_PORT_SL_MAP_SUP
        IBV_PORT_MKEY_NVRAM
        IBV_PORT_PKEY_NVRAM
        IBV_PORT_LED_INFO_SUP
        IBV_PORT_SYS_IMAGE_GUID_SUP
        IBV_PORT_PKEY_SW_EXT_PORT_TRAP_SUP
        IBV_PORT_EXTENDED_SPEEDS_SUP
        IBV_PORT_CAP_MASK2_SUP
        IBV_PORT_CM_SUP
        IBV_PORT_SNMP_TUNNEL_SUP
        IBV_PORT_REINIT_SUP
        IBV_PORT_DEVICE_MGMT_SUP
        IBV_PORT_VENDOR_CLASS_SUP
        IBV_PORT_DR_NOTICE_SUP
        IBV_PORT_CAP_MASK_NOTICE_SUP
        IBV_PORT_BOOT_MGMT_SUP
        IBV_PORT_LINK_LATENCY_SUP
        IBV_PORT_CLIENT_REG_SUP
        IBV_PORT_IP_BASED_GIDS

    cpdef enum ibv_port_cap_flags2:
        IBV_PORT_SET_NODE_DESC_SUP
        IBV_PORT_INFO_EXT_SUP
        IBV_PORT_VIRT_SUP
        IBV_PORT_SWITCH_PORT_STATE_TABLE_SUP
        IBV_PORT_LINK_WIDTH_2X_SUP
        IBV_PORT_LINK_SPEED_HDR_SUP

    cpdef enum ibv_mtu:
        IBV_MTU_256
        IBV_MTU_512
        IBV_MTU_1024
        IBV_MTU_2048
        IBV_MTU_4096

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
        IBV_ACCESS_LOCAL_WRITE
        IBV_ACCESS_REMOTE_WRITE
        IBV_ACCESS_REMOTE_READ
        IBV_ACCESS_REMOTE_ATOMIC
        IBV_ACCESS_MW_BIND
        IBV_ACCESS_ZERO_BASED
        IBV_ACCESS_ON_DEMAND
        IBV_ACCESS_HUGETLB
        IBV_ACCESS_RELAXED_ORDERING

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
        IBV_SEND_FENCE
        IBV_SEND_SIGNALED
        IBV_SEND_SOLICITED
        IBV_SEND_INLINE
        IBV_SEND_IP_CSUM

    cpdef enum ibv_qp_type:
        IBV_QPT_RC
        IBV_QPT_UC
        IBV_QPT_UD
        IBV_QPT_RAW_PACKET
        IBV_QPT_XRC_SEND
        IBV_QPT_XRC_RECV
        IBV_QPT_DRIVER

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
        IBV_MW_TYPE_1
        IBV_MW_TYPE_2

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
        IBV_WC_RECV
        IBV_WC_RECV_RDMA_WITH_IMM

    cpdef enum ibv_create_cq_wc_flags:
        IBV_WC_EX_WITH_BYTE_LEN
        IBV_WC_EX_WITH_IMM
        IBV_WC_EX_WITH_QP_NUM
        IBV_WC_EX_WITH_SRC_QP
        IBV_WC_EX_WITH_SLID
        IBV_WC_EX_WITH_SL
        IBV_WC_EX_WITH_DLID_PATH_BITS
        IBV_WC_EX_WITH_COMPLETION_TIMESTAMP
        IBV_WC_EX_WITH_CVLAN
        IBV_WC_EX_WITH_FLOW_TAG
        IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK

    cpdef enum ibv_wc_flags:
        IBV_WC_GRH
        IBV_WC_WITH_IMM
        IBV_WC_IP_CSUM_OK
        IBV_WC_WITH_INV

    cpdef enum ibv_srq_attr_mask:
        IBV_SRQ_MAX_WR
        IBV_SRQ_LIMIT

    cpdef enum ibv_srq_type:
        IBV_SRQT_BASIC
        IBV_SRQT_XRC

    cpdef enum ibv_srq_init_attr_mask:
        IBV_SRQ_INIT_ATTR_TYPE
        IBV_SRQ_INIT_ATTR_PD
        IBV_SRQ_INIT_ATTR_XRCD
        IBV_SRQ_INIT_ATTR_CQ

    cpdef enum ibv_mig_state:
        IBV_MIG_MIGRATED
        IBV_MIG_REARM
        IBV_MIG_ARMED

    cpdef enum ibv_qp_init_attr_mask:
        IBV_QP_INIT_ATTR_PD
        IBV_QP_INIT_ATTR_XRCD
        IBV_QP_INIT_ATTR_CREATE_FLAGS
        IBV_QP_INIT_ATTR_MAX_TSO_HEADER
        IBV_QP_INIT_ATTR_IND_TABLE
        IBV_QP_INIT_ATTR_RX_HASH

    cpdef enum ibv_qp_create_flags:
        IBV_QP_CREATE_BLOCK_SELF_MCAST_LB
        IBV_QP_CREATE_SCATTER_FCS
        IBV_QP_CREATE_CVLAN_STRIPPING
        IBV_QP_CREATE_SOURCE_QPN
        IBV_QP_CREATE_PCI_WRITE_END_PADDING

    cpdef enum ibv_qp_attr_mask:
        IBV_QP_STATE
        IBV_QP_CUR_STATE
        IBV_QP_EN_SQD_ASYNC_NOTIFY
        IBV_QP_ACCESS_FLAGS
        IBV_QP_PKEY_INDEX
        IBV_QP_PORT
        IBV_QP_QKEY
        IBV_QP_AV
        IBV_QP_PATH_MTU
        IBV_QP_TIMEOUT
        IBV_QP_RETRY_CNT
        IBV_QP_RNR_RETRY
        IBV_QP_RQ_PSN
        IBV_QP_MAX_QP_RD_ATOMIC
        IBV_QP_ALT_PATH
        IBV_QP_MIN_RNR_TIMER
        IBV_QP_SQ_PSN
        IBV_QP_MAX_DEST_RD_ATOMIC
        IBV_QP_PATH_MIG_STATE
        IBV_QP_CAP
        IBV_QP_DEST_QPN
        IBV_QP_RATE_LIMIT

    cpdef enum ibv_wq_type:
        IBV_WQT_RQ

    cpdef enum ibv_wq_init_attr_mask:
        IBV_WQ_INIT_ATTR_FLAGS

    cpdef enum ibv_wq_flags:
        IBV_WQ_FLAGS_CVLAN_STRIPPING
        IBV_WQ_FLAGS_SCATTER_FCS
        IBV_WQ_FLAGS_DELAY_DROP
        IBV_WQ_FLAGS_PCI_WRITE_END_PADDING

    cpdef enum ibv_wq_state:
        IBV_WQS_RESET
        IBV_WQS_RDY
        IBV_WQS_ERR
        IBV_WQS_UNKNOWN

    cpdef enum ibv_wq_attr_mask:
        IBV_WQ_ATTR_STATE
        IBV_WQ_ATTR_CURR_STATE
        IBV_WQ_ATTR_FLAGS

    cpdef enum ibv_rx_hash_function_flags:
        IBV_RX_HASH_FUNC_TOEPLITZ

    cpdef enum ibv_rx_hash_fields:
        IBV_RX_HASH_SRC_IPV4
        IBV_RX_HASH_DST_IPV4
        IBV_RX_HASH_SRC_IPV6
        IBV_RX_HASH_DST_IPV6
        IBV_RX_HASH_SRC_PORT_TCP
        IBV_RX_HASH_DST_PORT_TCP
        IBV_RX_HASH_SRC_PORT_UDP
        IBV_RX_HASH_DST_PORT_UDP

    cpdef enum ibv_flow_flags:
        IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK
        IBV_FLOW_ATTR_FLAGS_DONT_TRAP
        IBV_FLOW_ATTR_FLAGS_EGRESS

    cpdef enum ibv_flow_attr_type:
        IBV_FLOW_ATTR_NORMAL
        IBV_FLOW_ATTR_ALL_DEFAULT
        IBV_FLOW_ATTR_MC_DEFAULT
        IBV_FLOW_ATTR_SNIFFER

    cpdef enum ibv_flow_spec_type:
        IBV_FLOW_SPEC_ETH
        IBV_FLOW_SPEC_IPV4
        IBV_FLOW_SPEC_IPV6
        IBV_FLOW_SPEC_IPV4_EXT
        IBV_FLOW_SPEC_ESP
        IBV_FLOW_SPEC_TCP
        IBV_FLOW_SPEC_UDP
        IBV_FLOW_SPEC_VXLAN_TUNNEL
        IBV_FLOW_SPEC_GRE
        IBV_FLOW_SPEC_MPLS
        IBV_FLOW_SPEC_INNER
        IBV_FLOW_SPEC_ACTION_TAG
        IBV_FLOW_SPEC_ACTION_DROP
        IBV_FLOW_SPEC_ACTION_HANDLE
        IBV_FLOW_SPEC_ACTION_COUNT

    cpdef enum:
        IBV_QPF_GRH_REQUIRED

    cpdef enum ibv_counter_description:
        IBV_COUNTER_PACKETS
        IBV_COUNTER_BYTES

    cpdef enum ibv_read_counters_flags:
        IBV_READ_COUNTERS_ATTR_PREFER_CACHED

    cpdef enum ibv_cq_init_attr_mask:
        IBV_CQ_INIT_ATTR_MASK_FLAGS

    cpdef enum ibv_create_cq_attr_flags:
        IBV_CREATE_CQ_ATTR_SINGLE_THREADED
        IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN

    cpdef enum ibv_odp_general_caps:
        IBV_ODP_SUPPORT
        IBV_ODP_SUPPORT_IMPLICIT

    cpdef enum ibv_odp_transport_cap_bits:
        IBV_ODP_SUPPORT_SEND
        IBV_ODP_SUPPORT_RECV
        IBV_ODP_SUPPORT_WRITE
        IBV_ODP_SUPPORT_READ
        IBV_ODP_SUPPORT_ATOMIC
        IBV_ODP_SUPPORT_SRQ_RECV

    cpdef enum ibv_device_cap_flags:
        IBV_DEVICE_RESIZE_MAX_WR
        IBV_DEVICE_BAD_PKEY_CNTR
        IBV_DEVICE_BAD_QKEY_CNTR
        IBV_DEVICE_RAW_MULTI
        IBV_DEVICE_AUTO_PATH_MIG
        IBV_DEVICE_CHANGE_PHY_PORT
        IBV_DEVICE_UD_AV_PORT_ENFORCE
        IBV_DEVICE_CURR_QP_STATE_MOD
        IBV_DEVICE_SHUTDOWN_PORT
        IBV_DEVICE_INIT_TYPE
        IBV_DEVICE_PORT_ACTIVE_EVENT
        IBV_DEVICE_SYS_IMAGE_GUID
        IBV_DEVICE_RC_RNR_NAK_GEN
        IBV_DEVICE_SRQ_RESIZE
        IBV_DEVICE_N_NOTIFY_CQ
        IBV_DEVICE_MEM_WINDOW
        IBV_DEVICE_UD_IP_CSUM
        IBV_DEVICE_XRC
        IBV_DEVICE_MEM_MGT_EXTENSIONS
        IBV_DEVICE_MEM_WINDOW_TYPE_2A
        IBV_DEVICE_MEM_WINDOW_TYPE_2B
        IBV_DEVICE_RC_IP_CSUM
        IBV_DEVICE_RAW_IP_CSUM
        IBV_DEVICE_MANAGED_FLOW_STEERING

    cpdef enum ibv_raw_packet_caps:
        IBV_RAW_PACKET_CAP_CVLAN_STRIPPING
        IBV_RAW_PACKET_CAP_SCATTER_FCS
        IBV_RAW_PACKET_CAP_IP_CSUM
        IBV_RAW_PACKET_CAP_DELAY_DROP

    cpdef enum ibv_xrcd_init_attr_mask:
        IBV_XRCD_INIT_ATTR_FD
        IBV_XRCD_INIT_ATTR_OFLAGS
        IBV_XRCD_INIT_ATTR_RESERVED

    cpdef enum:
        IBV_WC_STANDARD_FLAGS

    cdef unsigned long long IBV_DEVICE_RAW_SCATTER_FCS
    cdef unsigned long long IBV_DEVICE_PCI_WRITE_END_PADDING

    cpdef enum ibv_parent_domain_init_attr_mask:
        IBV_PARENT_DOMAIN_INIT_ATTR_ALLOCATORS
        IBV_PARENT_DOMAIN_INIT_ATTR_PD_CONTEXT

    cdef void *IBV_ALLOCATOR_USE_DEFAULT


_IBV_DEVICE_RAW_SCATTER_FCS = IBV_DEVICE_RAW_SCATTER_FCS
_IBV_DEVICE_PCI_WRITE_END_PADDING = IBV_DEVICE_PCI_WRITE_END_PADDING
_IBV_ALLOCATOR_USE_DEFAULT = <size_t>IBV_ALLOCATOR_USE_DEFAULT
