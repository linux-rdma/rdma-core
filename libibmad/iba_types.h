/*
 * Copyright (c) 2004-2009 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2002-2019 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 1996-2003 Intel Corporation. All rights reserved.
 * Copyright (c) 2009 HNR Consulting. All rights reserved.
 * Copyright (c) 2013 Oracle and/or its affiliates. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef __LIBIBMAD_IB_TYPES_H__
#define __LIBIBMAD_IB_TYPES_H__

#include <endian.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <linux/types.h>

#define MAD_BLOCK_SIZE 256
#define MAD_RMPP_HDR_SIZE 36
#define MAD_BLOCK_GRH_SIZE 296
#define IB_LID_PERMISSIVE 0xFFFF
#define IB_DEFAULT_PKEY 0xFFFF
#define IB_QP1_WELL_KNOWN_Q_KEY htobe32(0x80010000)
#define IB_QP0 0
#define IB_QP1 htobe32(1)
#define IB_QP_PRIVILEGED_Q_KEY htobe32(0x80000000)
#define IB_LID_UCAST_START_HO 0x0001
#define IB_LID_UCAST_START htobe16(IB_LID_UCAST_START_HO)
#define IB_LID_UCAST_END_HO 0xBFFF
#define IB_LID_UCAST_END htobe16(IB_LID_UCAST_END_HO)
#define IB_LID_MCAST_START_HO 0xC000
#define IB_LID_MCAST_START htobe16(IB_LID_MCAST_START_HO)
#define IB_LID_MCAST_END_HO 0xFFFE
#define IB_LID_MCAST_END htobe16(IB_LID_MCAST_END_HO)
#define IB_DEFAULT_SUBNET_PREFIX htobe64(0xFE80000000000000ULL)
#define IB_DEFAULT_SUBNET_PREFIX_HO 0xFE80000000000000ULL
#define IB_NODE_NUM_PORTS_MAX 0xFE
#define IB_INVALID_PORT_NUM 0xFF
#define IB_SUBNET_PATH_HOPS_MAX 64
#define IB_HOPLIMIT_MAX 255
#define IB_MC_SCOPE_LINK_LOCAL 0x2
#define IB_MC_SCOPE_SITE_LOCAL 0x5
#define IB_MC_SCOPE_ORG_LOCAL 0x8
#define IB_MC_SCOPE_GLOBAL 0xE
#define IB_PKEY_MAX_BLOCKS 2048
#define IB_MCAST_MAX_BLOCK_ID 511
#define IB_MCAST_BLOCK_ID_MASK_HO 0x000001FF
#define IB_MCAST_BLOCK_SIZE 32
#define IB_MCAST_MASK_SIZE 16
#define IB_MCAST_POSITION_MASK_HO 0xF0000000
#define IB_MCAST_POSITION_MAX 0xF
#define IB_MCAST_POSITION_SHIFT 28
#define IB_PKEY_BASE_MASK htobe16(0x7FFF)
#define IB_PKEY_TYPE_MASK htobe16(0x8000)
#define IB_DEFAULT_PARTIAL_PKEY htobe16(0x7FFF)
#define IB_MCLASS_SUBN_LID 0x01
#define IB_MCLASS_SUBN_DIR 0x81
#define IB_MCLASS_SUBN_ADM 0x03
#define IB_MCLASS_PERF 0x04
#define IB_MCLASS_BM 0x05
#define IB_MCLASS_DEV_MGMT 0x06
#define IB_MCLASS_COMM_MGMT 0x07
#define IB_MCLASS_SNMP 0x08
#define IB_MCLASS_VENDOR_LOW_RANGE_MIN 0x09
#define IB_MCLASS_VENDOR_LOW_RANGE_MAX 0x0F
#define IB_MCLASS_DEV_ADM 0x10
#define IB_MCLASS_BIS 0x12
#define IB_MCLASS_CC 0x21
#define IB_MCLASS_VENDOR_HIGH_RANGE_MIN 0x30
#define IB_MCLASS_VENDOR_HIGH_RANGE_MAX 0x4F
#define IB_MAX_METHODS 128
#define IB_MAD_METHOD_RESP_MASK 0x80
#define IB_MAD_METHOD_GET 0x01
#define IB_MAD_METHOD_SET 0x02
#define IB_MAD_METHOD_GET_RESP 0x81
#define IB_MAD_METHOD_DELETE 0x15
#define IB_MAD_METHOD_GETTABLE 0x12
#define IB_MAD_METHOD_GETTABLE_RESP 0x92
#define IB_MAD_METHOD_GETTRACETABLE 0x13
#define IB_MAD_METHOD_GETMULTI 0x14
#define IB_MAD_METHOD_GETMULTI_RESP 0x94
#define IB_MAD_METHOD_SEND 0x03
#define IB_MAD_METHOD_TRAP 0x05
#define IB_MAD_METHOD_REPORT 0x06
#define IB_MAD_METHOD_REPORT_RESP 0x86
#define IB_MAD_METHOD_TRAP_REPRESS 0x07
#define IB_MAD_STATUS_BUSY htobe16(0x0001)
#define IB_MAD_STATUS_REDIRECT htobe16(0x0002)
#define IB_MAD_STATUS_UNSUP_CLASS_VER htobe16(0x0004)
#define IB_MAD_STATUS_UNSUP_METHOD htobe16(0x0008)
#define IB_MAD_STATUS_UNSUP_METHOD_ATTR htobe16(0x000C)
#define IB_MAD_STATUS_INVALID_FIELD htobe16(0x001C)
#define IB_MAD_STATUS_CLASS_MASK htobe16(0xFF00)
#define IB_SA_MAD_STATUS_SUCCESS 0x0000
#define IB_SA_MAD_STATUS_NO_RESOURCES htobe16(0x0100)
#define IB_SA_MAD_STATUS_REQ_INVALID htobe16(0x0200)
#define IB_SA_MAD_STATUS_NO_RECORDS htobe16(0x0300)
#define IB_SA_MAD_STATUS_TOO_MANY_RECORDS htobe16(0x0400)
#define IB_SA_MAD_STATUS_INVALID_GID htobe16(0x0500)
#define IB_SA_MAD_STATUS_INSUF_COMPS htobe16(0x0600)
#define IB_SA_MAD_STATUS_DENIED htobe16(0x0700)
#define IB_SA_MAD_STATUS_PRIO_SUGGESTED htobe16(0x0800)
#define IB_DM_MAD_STATUS_NO_IOC_RESP htobe16(0x0100)
#define IB_DM_MAD_STATUS_NO_SVC_ENTRIES htobe16(0x0200)
#define IB_DM_MAD_STATUS_IOC_FAILURE htobe16(0x8000)
#define IB_MAD_ATTR_CLASS_PORT_INFO htobe16(0x0001)
#define IB_MAD_ATTR_NOTICE htobe16(0x0002)
#define IB_MAD_ATTR_INFORM_INFO htobe16(0x0003)
#define IB_MAD_ATTR_NODE_DESC htobe16(0x0010)
#define IB_MAD_ATTR_PORT_SMPL_CTRL htobe16(0x0010)
#define IB_MAD_ATTR_NODE_INFO htobe16(0x0011)
#define IB_MAD_ATTR_PORT_SMPL_RSLT htobe16(0x0011)
#define IB_MAD_ATTR_SWITCH_INFO htobe16(0x0012)
#define IB_MAD_ATTR_PORT_CNTRS htobe16(0x0012)
#define IB_MAD_ATTR_PORT_CNTRS_EXT htobe16(0x001D)
#define IB_MAD_ATTR_PORT_XMIT_DATA_SL htobe16(0x0036)
#define IB_MAD_ATTR_PORT_RCV_DATA_SL htobe16(0x0037)
#define IB_MAD_ATTR_GUID_INFO htobe16(0x0014)
#define IB_MAD_ATTR_PORT_INFO htobe16(0x0015)
#define IB_MAD_ATTR_P_KEY_TABLE htobe16(0x0016)
#define IB_MAD_ATTR_SLVL_TABLE htobe16(0x0017)
#define IB_MAD_ATTR_VL_ARBITRATION htobe16(0x0018)
#define IB_MAD_ATTR_LIN_FWD_TBL htobe16(0x0019)
#define IB_MAD_ATTR_RND_FWD_TBL htobe16(0x001A)
#define IB_MAD_ATTR_MCAST_FWD_TBL htobe16(0x001B)
#define IB_MAD_ATTR_NODE_RECORD htobe16(0x0011)
#define IB_MAD_ATTR_PORTINFO_RECORD htobe16(0x0012)
#define IB_MAD_ATTR_SWITCH_INFO_RECORD htobe16(0x0014)
#define IB_MAD_ATTR_LINK_RECORD htobe16(0x0020)
#define IB_MAD_ATTR_SM_INFO htobe16(0x0020)
#define IB_MAD_ATTR_SMINFO_RECORD htobe16(0x0018)
#define IB_MAD_ATTR_GUIDINFO_RECORD htobe16(0x0030)
#define IB_MAD_ATTR_VENDOR_DIAG htobe16(0x0030)
#define IB_MAD_ATTR_LED_INFO htobe16(0x0031)
#define IB_MAD_ATTR_MLNX_EXTENDED_PORT_INFO htobe16(0xFF90)
#define IB_MAD_ATTR_SERVICE_RECORD htobe16(0x0031)
#define IB_MAD_ATTR_LFT_RECORD htobe16(0x0015)
#define IB_MAD_ATTR_MFT_RECORD htobe16(0x0017)
#define IB_MAD_ATTR_PKEY_TBL_RECORD htobe16(0x0033)
#define IB_MAD_ATTR_PATH_RECORD htobe16(0x0035)
#define IB_MAD_ATTR_VLARB_RECORD htobe16(0x0036)
#define IB_MAD_ATTR_SLVL_RECORD htobe16(0x0013)
#define IB_MAD_ATTR_MCMEMBER_RECORD htobe16(0x0038)
#define IB_MAD_ATTR_TRACE_RECORD htobe16(0x0039)
#define IB_MAD_ATTR_MULTIPATH_RECORD htobe16(0x003A)
#define IB_MAD_ATTR_SVC_ASSOCIATION_RECORD htobe16(0x003B)
#define IB_MAD_ATTR_INFORM_INFO_RECORD htobe16(0x00F3)
#define IB_MAD_ATTR_IO_UNIT_INFO htobe16(0x0010)
#define IB_MAD_ATTR_IO_CONTROLLER_PROFILE htobe16(0x0011)
#define IB_MAD_ATTR_SERVICE_ENTRIES htobe16(0x0012)
#define IB_MAD_ATTR_DIAGNOSTIC_TIMEOUT htobe16(0x0020)
#define IB_MAD_ATTR_PREPARE_TO_TEST htobe16(0x0021)
#define IB_MAD_ATTR_TEST_DEVICE_ONCE htobe16(0x0022)
#define IB_MAD_ATTR_TEST_DEVICE_LOOP htobe16(0x0023)
#define IB_MAD_ATTR_DIAG_CODE htobe16(0x0024)
#define IB_MAD_ATTR_SVC_ASSOCIATION_RECORD htobe16(0x003B)
#define IB_MAD_ATTR_CONG_INFO htobe16(0x0011)
#define IB_MAD_ATTR_CONG_KEY_INFO htobe16(0x0012)
#define IB_MAD_ATTR_CONG_LOG htobe16(0x0013)
#define IB_MAD_ATTR_SW_CONG_SETTING htobe16(0x0014)
#define IB_MAD_ATTR_SW_PORT_CONG_SETTING htobe16(0x0015)
#define IB_MAD_ATTR_CA_CONG_SETTING htobe16(0x0016)
#define IB_MAD_ATTR_CC_TBL htobe16(0x0017)
#define IB_MAD_ATTR_TIME_STAMP htobe16(0x0018)
#define IB_NODE_TYPE_CA 0x01
#define IB_NODE_TYPE_SWITCH 0x02
#define IB_NODE_TYPE_ROUTER 0x03
#define IB_NOTICE_PRODUCER_TYPE_CA htobe32(0x000001)
#define IB_NOTICE_PRODUCER_TYPE_SWITCH htobe32(0x000002)
#define IB_NOTICE_PRODUCER_TYPE_ROUTER htobe32(0x000003)
#define IB_NOTICE_PRODUCER_TYPE_CLASS_MGR htobe32(0x000004)
#define IB_MTU_LEN_256 1
#define IB_MTU_LEN_512 2
#define IB_MTU_LEN_1024 3
#define IB_MTU_LEN_2048 4
#define IB_MTU_LEN_4096 5
#define IB_PATH_SELECTOR_GREATER_THAN 0
#define IB_PATH_SELECTOR_LESS_THAN 1
#define IB_PATH_SELECTOR_EXACTLY 2
#define IB_PATH_SELECTOR_LARGEST 3
#define IB_SMINFO_STATE_NOTACTIVE 0
#define IB_SMINFO_STATE_DISCOVERING 1
#define IB_SMINFO_STATE_STANDBY 2
#define IB_SMINFO_STATE_MASTER 3
#define IB_PATH_REC_SL_MASK 0x000F
#define IB_MULTIPATH_REC_SL_MASK 0x000F
#define IB_PATH_REC_QOS_CLASS_MASK 0xFFF0
#define IB_MULTIPATH_REC_QOS_CLASS_MASK 0xFFF0
#define IB_PATH_REC_SELECTOR_MASK 0xC0
#define IB_MULTIPATH_REC_SELECTOR_MASK 0xC0
#define IB_PATH_REC_BASE_MASK 0x3F
#define IB_MULTIPATH_REC_BASE_MASK 0x3F
#define IB_LINK_NO_CHANGE 0
#define IB_LINK_DOWN 1
#define IB_LINK_INIT 2
#define IB_LINK_ARMED 3
#define IB_LINK_ACTIVE 4
#define IB_LINK_ACT_DEFER 5
#define IB_JOIN_STATE_FULL 1
#define IB_JOIN_STATE_NON 2
#define IB_JOIN_STATE_SEND_ONLY 4
#define IB_JOIN_STATE_SEND_ONLY_FULL 8
typedef union {
	uint8_t raw[16];
	struct _ib_gid_unicast {
		__be64 prefix;
		__be64 interface_id;
	} __attribute__((packed)) unicast;
	struct _ib_gid_multicast {
		uint8_t header[2];
		uint8_t raw_group_id[14];
	} __attribute__((packed)) multicast;
	struct _ib_gid_ip_multicast {
		uint8_t header[2];
		__be16 signature;
		__be16 p_key;
		uint8_t group_id[10];
	} __attribute__((packed)) ip_multicast;
} __attribute__((packed)) ib_gid_t;
typedef struct {
	__be64 service_id;
	ib_gid_t dgid;
	ib_gid_t sgid;
	__be16 dlid;
	__be16 slid;
	__be32 hop_flow_raw;
	uint8_t tclass;
	uint8_t num_path;
	__be16 pkey;
	__be16 qos_class_sl;
	uint8_t mtu;
	uint8_t rate;
	uint8_t pkt_life;
	uint8_t preference;
	uint8_t resv2[6];
} __attribute__((packed)) ib_path_rec_t;
#define IB_PR_COMPMASK_SERVICEID_MSB htobe64(((uint64_t)1) << 0)
#define IB_PR_COMPMASK_SERVICEID_LSB htobe64(((uint64_t)1) << 1)
#define IB_PR_COMPMASK_DGID htobe64(((uint64_t)1) << 2)
#define IB_PR_COMPMASK_SGID htobe64(((uint64_t)1) << 3)
#define IB_PR_COMPMASK_DLID htobe64(((uint64_t)1) << 4)
#define IB_PR_COMPMASK_SLID htobe64(((uint64_t)1) << 5)
#define IB_PR_COMPMASK_RAWTRAFFIC htobe64(((uint64_t)1) << 6)
#define IB_PR_COMPMASK_RESV0 htobe64(((uint64_t)1) << 7)
#define IB_PR_COMPMASK_FLOWLABEL htobe64(((uint64_t)1) << 8)
#define IB_PR_COMPMASK_HOPLIMIT htobe64(((uint64_t)1) << 9)
#define IB_PR_COMPMASK_TCLASS htobe64(((uint64_t)1) << 10)
#define IB_PR_COMPMASK_REVERSIBLE htobe64(((uint64_t)1) << 11)
#define IB_PR_COMPMASK_NUMBPATH htobe64(((uint64_t)1) << 12)
#define IB_PR_COMPMASK_PKEY htobe64(((uint64_t)1) << 13)
#define IB_PR_COMPMASK_QOS_CLASS htobe64(((uint64_t)1) << 14)
#define IB_PR_COMPMASK_SL htobe64(((uint64_t)1) << 15)
#define IB_PR_COMPMASK_MTUSELEC htobe64(((uint64_t)1) << 16)
#define IB_PR_COMPMASK_MTU htobe64(((uint64_t)1) << 17)
#define IB_PR_COMPMASK_RATESELEC htobe64(((uint64_t)1) << 18)
#define IB_PR_COMPMASK_RATE htobe64(((uint64_t)1) << 19)
#define IB_PR_COMPMASK_PKTLIFETIMESELEC htobe64(((uint64_t)1) << 20)
#define IB_PR_COMPMASK_PKTLIFETIME htobe64(((uint64_t)1) << 21)
#define IB_LR_COMPMASK_FROM_LID htobe64(((uint64_t)1) << 0)
#define IB_LR_COMPMASK_FROM_PORT htobe64(((uint64_t)1) << 1)
#define IB_LR_COMPMASK_TO_PORT htobe64(((uint64_t)1) << 2)
#define IB_LR_COMPMASK_TO_LID htobe64(((uint64_t)1) << 3)
#define IB_VLA_COMPMASK_LID htobe64(((uint64_t)1) << 0)
#define IB_VLA_COMPMASK_OUT_PORT htobe64(((uint64_t)1) << 1)
#define IB_VLA_COMPMASK_BLOCK htobe64(((uint64_t)1) << 2)
#define IB_SLVL_COMPMASK_LID htobe64(((uint64_t)1) << 0)
#define IB_SLVL_COMPMASK_IN_PORT htobe64(((uint64_t)1) << 1)
#define IB_SLVL_COMPMASK_OUT_PORT htobe64(((uint64_t)1) << 2)
#define IB_PKEY_COMPMASK_LID htobe64(((uint64_t)1) << 0)
#define IB_PKEY_COMPMASK_BLOCK htobe64(((uint64_t)1) << 1)
#define IB_PKEY_COMPMASK_PORT htobe64(((uint64_t)1) << 2)
#define IB_SWIR_COMPMASK_LID htobe64(((uint64_t)1) << 0)
#define IB_SWIR_COMPMASK_RESERVED1 htobe64(((uint64_t)1) << 1)
#define IB_LFTR_COMPMASK_LID htobe64(((uint64_t)1) << 0)
#define IB_LFTR_COMPMASK_BLOCK htobe64(((uint64_t)1) << 1)
#define IB_MFTR_COMPMASK_LID htobe64(((uint64_t)1) << 0)
#define IB_MFTR_COMPMASK_POSITION htobe64(((uint64_t)1) << 1)
#define IB_MFTR_COMPMASK_RESERVED1 htobe64(((uint64_t)1) << 2)
#define IB_MFTR_COMPMASK_BLOCK htobe64(((uint64_t)1) << 3)
#define IB_MFTR_COMPMASK_RESERVED2 htobe64(((uint64_t)1) << 4)
#define IB_NR_COMPMASK_LID htobe64(((uint64_t)1) << 0)
#define IB_NR_COMPMASK_RESERVED1 htobe64(((uint64_t)1) << 1)
#define IB_NR_COMPMASK_BASEVERSION htobe64(((uint64_t)1) << 2)
#define IB_NR_COMPMASK_CLASSVERSION htobe64(((uint64_t)1) << 3)
#define IB_NR_COMPMASK_NODETYPE htobe64(((uint64_t)1) << 4)
#define IB_NR_COMPMASK_NUMPORTS htobe64(((uint64_t)1) << 5)
#define IB_NR_COMPMASK_SYSIMAGEGUID htobe64(((uint64_t)1) << 6)
#define IB_NR_COMPMASK_NODEGUID htobe64(((uint64_t)1) << 7)
#define IB_NR_COMPMASK_PORTGUID htobe64(((uint64_t)1) << 8)
#define IB_NR_COMPMASK_PARTCAP htobe64(((uint64_t)1) << 9)
#define IB_NR_COMPMASK_DEVID htobe64(((uint64_t)1) << 10)
#define IB_NR_COMPMASK_REV htobe64(((uint64_t)1) << 11)
#define IB_NR_COMPMASK_PORTNUM htobe64(((uint64_t)1) << 12)
#define IB_NR_COMPMASK_VENDID htobe64(((uint64_t)1) << 13)
#define IB_NR_COMPMASK_NODEDESC htobe64(((uint64_t)1) << 14)
#define IB_SR_COMPMASK_SID htobe64(((uint64_t)1) << 0)
#define IB_SR_COMPMASK_SGID htobe64(((uint64_t)1) << 1)
#define IB_SR_COMPMASK_SPKEY htobe64(((uint64_t)1) << 2)
#define IB_SR_COMPMASK_RES1 htobe64(((uint64_t)1) << 3)
#define IB_SR_COMPMASK_SLEASE htobe64(((uint64_t)1) << 4)
#define IB_SR_COMPMASK_SKEY htobe64(((uint64_t)1) << 5)
#define IB_SR_COMPMASK_SNAME htobe64(((uint64_t)1) << 6)
#define IB_SR_COMPMASK_SDATA8_0 htobe64(((uint64_t)1) << 7)
#define IB_SR_COMPMASK_SDATA8_1 htobe64(((uint64_t)1) << 8)
#define IB_SR_COMPMASK_SDATA8_2 htobe64(((uint64_t)1) << 9)
#define IB_SR_COMPMASK_SDATA8_3 htobe64(((uint64_t)1) << 10)
#define IB_SR_COMPMASK_SDATA8_4 htobe64(((uint64_t)1) << 11)
#define IB_SR_COMPMASK_SDATA8_5 htobe64(((uint64_t)1) << 12)
#define IB_SR_COMPMASK_SDATA8_6 htobe64(((uint64_t)1) << 13)
#define IB_SR_COMPMASK_SDATA8_7 htobe64(((uint64_t)1) << 14)
#define IB_SR_COMPMASK_SDATA8_8 htobe64(((uint64_t)1) << 15)
#define IB_SR_COMPMASK_SDATA8_9 htobe64(((uint64_t)1) << 16)
#define IB_SR_COMPMASK_SDATA8_10 htobe64(((uint64_t)1) << 17)
#define IB_SR_COMPMASK_SDATA8_11 htobe64(((uint64_t)1) << 18)
#define IB_SR_COMPMASK_SDATA8_12 htobe64(((uint64_t)1) << 19)
#define IB_SR_COMPMASK_SDATA8_13 htobe64(((uint64_t)1) << 20)
#define IB_SR_COMPMASK_SDATA8_14 htobe64(((uint64_t)1) << 21)
#define IB_SR_COMPMASK_SDATA8_15 htobe64(((uint64_t)1) << 22)
#define IB_SR_COMPMASK_SDATA16_0 htobe64(((uint64_t)1) << 23)
#define IB_SR_COMPMASK_SDATA16_1 htobe64(((uint64_t)1) << 24)
#define IB_SR_COMPMASK_SDATA16_2 htobe64(((uint64_t)1) << 25)
#define IB_SR_COMPMASK_SDATA16_3 htobe64(((uint64_t)1) << 26)
#define IB_SR_COMPMASK_SDATA16_4 htobe64(((uint64_t)1) << 27)
#define IB_SR_COMPMASK_SDATA16_5 htobe64(((uint64_t)1) << 28)
#define IB_SR_COMPMASK_SDATA16_6 htobe64(((uint64_t)1) << 29)
#define IB_SR_COMPMASK_SDATA16_7 htobe64(((uint64_t)1) << 30)
#define IB_SR_COMPMASK_SDATA32_0 htobe64(((uint64_t)1) << 31)
#define IB_SR_COMPMASK_SDATA32_1 htobe64(((uint64_t)1) << 32)
#define IB_SR_COMPMASK_SDATA32_2 htobe64(((uint64_t)1) << 33)
#define IB_SR_COMPMASK_SDATA32_3 htobe64(((uint64_t)1) << 34)
#define IB_SR_COMPMASK_SDATA64_0 htobe64(((uint64_t)1) << 35)
#define IB_SR_COMPMASK_SDATA64_1 htobe64(((uint64_t)1) << 36)
#define IB_PIR_COMPMASK_LID htobe64(((uint64_t)1) << 0)
#define IB_PIR_COMPMASK_PORTNUM htobe64(((uint64_t)1) << 1)
#define IB_PIR_COMPMASK_OPTIONS htobe64(((uint64_t)1) << 2)
#define IB_PIR_COMPMASK_MKEY htobe64(((uint64_t)1) << 3)
#define IB_PIR_COMPMASK_GIDPRE htobe64(((uint64_t)1) << 4)
#define IB_PIR_COMPMASK_BASELID htobe64(((uint64_t)1) << 5)
#define IB_PIR_COMPMASK_SMLID htobe64(((uint64_t)1) << 6)
#define IB_PIR_COMPMASK_CAPMASK htobe64(((uint64_t)1) << 7)
#define IB_PIR_COMPMASK_DIAGCODE htobe64(((uint64_t)1) << 8)
#define IB_PIR_COMPMASK_MKEYLEASEPRD htobe64(((uint64_t)1) << 9)
#define IB_PIR_COMPMASK_LOCALPORTNUM htobe64(((uint64_t)1) << 10)
#define IB_PIR_COMPMASK_LINKWIDTHENABLED htobe64(((uint64_t)1) << 11)
#define IB_PIR_COMPMASK_LNKWIDTHSUPPORT htobe64(((uint64_t)1) << 12)
#define IB_PIR_COMPMASK_LNKWIDTHACTIVE htobe64(((uint64_t)1) << 13)
#define IB_PIR_COMPMASK_LNKSPEEDSUPPORT htobe64(((uint64_t)1) << 14)
#define IB_PIR_COMPMASK_PORTSTATE htobe64(((uint64_t)1) << 15)
#define IB_PIR_COMPMASK_PORTPHYSTATE htobe64(((uint64_t)1) << 16)
#define IB_PIR_COMPMASK_LINKDWNDFLTSTATE htobe64(((uint64_t)1) << 17)
#define IB_PIR_COMPMASK_MKEYPROTBITS htobe64(((uint64_t)1) << 18)
#define IB_PIR_COMPMASK_RESV2 htobe64(((uint64_t)1) << 19)
#define IB_PIR_COMPMASK_LMC htobe64(((uint64_t)1) << 20)
#define IB_PIR_COMPMASK_LINKSPEEDACTIVE htobe64(((uint64_t)1) << 21)
#define IB_PIR_COMPMASK_LINKSPEEDENABLE htobe64(((uint64_t)1) << 22)
#define IB_PIR_COMPMASK_NEIGHBORMTU htobe64(((uint64_t)1) << 23)
#define IB_PIR_COMPMASK_MASTERSMSL htobe64(((uint64_t)1) << 24)
#define IB_PIR_COMPMASK_VLCAP htobe64(((uint64_t)1) << 25)
#define IB_PIR_COMPMASK_INITTYPE htobe64(((uint64_t)1) << 26)
#define IB_PIR_COMPMASK_VLHIGHLIMIT htobe64(((uint64_t)1) << 27)
#define IB_PIR_COMPMASK_VLARBHIGHCAP htobe64(((uint64_t)1) << 28)
#define IB_PIR_COMPMASK_VLARBLOWCAP htobe64(((uint64_t)1) << 29)
#define IB_PIR_COMPMASK_INITTYPEREPLY htobe64(((uint64_t)1) << 30)
#define IB_PIR_COMPMASK_MTUCAP htobe64(((uint64_t)1) << 31)
#define IB_PIR_COMPMASK_VLSTALLCNT htobe64(((uint64_t)1) << 32)
#define IB_PIR_COMPMASK_HOQLIFE htobe64(((uint64_t)1) << 33)
#define IB_PIR_COMPMASK_OPVLS htobe64(((uint64_t)1) << 34)
#define IB_PIR_COMPMASK_PARENFIN htobe64(((uint64_t)1) << 35)
#define IB_PIR_COMPMASK_PARENFOUT htobe64(((uint64_t)1) << 36)
#define IB_PIR_COMPMASK_FILTERRAWIN htobe64(((uint64_t)1) << 37)
#define IB_PIR_COMPMASK_FILTERRAWOUT htobe64(((uint64_t)1) << 38)
#define IB_PIR_COMPMASK_MKEYVIO htobe64(((uint64_t)1) << 39)
#define IB_PIR_COMPMASK_PKEYVIO htobe64(((uint64_t)1) << 40)
#define IB_PIR_COMPMASK_QKEYVIO htobe64(((uint64_t)1) << 41)
#define IB_PIR_COMPMASK_GUIDCAP htobe64(((uint64_t)1) << 42)
#define IB_PIR_COMPMASK_CLIENTREREG htobe64(((uint64_t)1) << 43)
#define IB_PIR_COMPMASK_RESV3 htobe64(((uint64_t)1) << 44)
#define IB_PIR_COMPMASK_SUBNTO htobe64(((uint64_t)1) << 45)
#define IB_PIR_COMPMASK_RESV4 htobe64(((uint64_t)1) << 46)
#define IB_PIR_COMPMASK_RESPTIME htobe64(((uint64_t)1) << 47)
#define IB_PIR_COMPMASK_LOCALPHYERR htobe64(((uint64_t)1) << 48)
#define IB_PIR_COMPMASK_OVERRUNERR htobe64(((uint64_t)1) << 49)
#define IB_PIR_COMPMASK_MAXCREDHINT htobe64(((uint64_t)1) << 50)
#define IB_PIR_COMPMASK_RESV5 htobe64(((uint64_t)1) << 51)
#define IB_PIR_COMPMASK_LINKRTLAT htobe64(((uint64_t)1) << 52)
#define IB_PIR_COMPMASK_CAPMASK2 htobe64(((uint64_t)1) << 53)
#define IB_PIR_COMPMASK_LINKSPDEXTACT htobe64(((uint64_t)1) << 54)
#define IB_PIR_COMPMASK_LINKSPDEXTSUPP htobe64(((uint64_t)1) << 55)
#define IB_PIR_COMPMASK_RESV7 htobe64(((uint64_t)1) << 56)
#define IB_PIR_COMPMASK_LINKSPDEXTENAB htobe64(((uint64_t)1) << 57)
#define IB_MCR_COMPMASK_GID htobe64(((uint64_t)1) << 0)
#define IB_MCR_COMPMASK_MGID htobe64(((uint64_t)1) << 0)
#define IB_MCR_COMPMASK_PORT_GID htobe64(((uint64_t)1) << 1)
#define IB_MCR_COMPMASK_QKEY htobe64(((uint64_t)1) << 2)
#define IB_MCR_COMPMASK_MLID htobe64(((uint64_t)1) << 3)
#define IB_MCR_COMPMASK_MTU_SEL htobe64(((uint64_t)1) << 4)
#define IB_MCR_COMPMASK_MTU htobe64(((uint64_t)1) << 5)
#define IB_MCR_COMPMASK_TCLASS htobe64(((uint64_t)1) << 6)
#define IB_MCR_COMPMASK_PKEY htobe64(((uint64_t)1) << 7)
#define IB_MCR_COMPMASK_RATE_SEL htobe64(((uint64_t)1) << 8)
#define IB_MCR_COMPMASK_RATE htobe64(((uint64_t)1) << 9)
#define IB_MCR_COMPMASK_LIFE_SEL htobe64(((uint64_t)1) << 10)
#define IB_MCR_COMPMASK_LIFE htobe64(((uint64_t)1) << 11)
#define IB_MCR_COMPMASK_SL htobe64(((uint64_t)1) << 12)
#define IB_MCR_COMPMASK_FLOW htobe64(((uint64_t)1) << 13)
#define IB_MCR_COMPMASK_HOP htobe64(((uint64_t)1) << 14)
#define IB_MCR_COMPMASK_SCOPE htobe64(((uint64_t)1) << 15)
#define IB_MCR_COMPMASK_JOIN_STATE htobe64(((uint64_t)1) << 16)
#define IB_MCR_COMPMASK_PROXY htobe64(((uint64_t)1) << 17)
#define IB_GIR_COMPMASK_LID htobe64(((uint64_t)1) << 0)
#define IB_GIR_COMPMASK_BLOCKNUM htobe64(((uint64_t)1) << 1)
#define IB_GIR_COMPMASK_RESV1 htobe64(((uint64_t)1) << 2)
#define IB_GIR_COMPMASK_RESV2 htobe64(((uint64_t)1) << 3)
#define IB_GIR_COMPMASK_GID0 htobe64(((uint64_t)1) << 4)
#define IB_GIR_COMPMASK_GID1 htobe64(((uint64_t)1) << 5)
#define IB_GIR_COMPMASK_GID2 htobe64(((uint64_t)1) << 6)
#define IB_GIR_COMPMASK_GID3 htobe64(((uint64_t)1) << 7)
#define IB_GIR_COMPMASK_GID4 htobe64(((uint64_t)1) << 8)
#define IB_GIR_COMPMASK_GID5 htobe64(((uint64_t)1) << 9)
#define IB_GIR_COMPMASK_GID6 htobe64(((uint64_t)1) << 10)
#define IB_GIR_COMPMASK_GID7 htobe64(((uint64_t)1) << 11)
#define IB_MPR_COMPMASK_RAWTRAFFIC htobe64(((uint64_t)1) << 0)
#define IB_MPR_COMPMASK_RESV0 htobe64(((uint64_t)1) << 1)
#define IB_MPR_COMPMASK_FLOWLABEL htobe64(((uint64_t)1) << 2)
#define IB_MPR_COMPMASK_HOPLIMIT htobe64(((uint64_t)1) << 3)
#define IB_MPR_COMPMASK_TCLASS htobe64(((uint64_t)1) << 4)
#define IB_MPR_COMPMASK_REVERSIBLE htobe64(((uint64_t)1) << 5)
#define IB_MPR_COMPMASK_NUMBPATH htobe64(((uint64_t)1) << 6)
#define IB_MPR_COMPMASK_PKEY htobe64(((uint64_t)1) << 7)
#define IB_MPR_COMPMASK_QOS_CLASS htobe64(((uint64_t)1) << 8)
#define IB_MPR_COMPMASK_SL htobe64(((uint64_t)1) << 9)
#define IB_MPR_COMPMASK_MTUSELEC htobe64(((uint64_t)1) << 10)
#define IB_MPR_COMPMASK_MTU htobe64(((uint64_t)1) << 11)
#define IB_MPR_COMPMASK_RATESELEC htobe64(((uint64_t)1) << 12)
#define IB_MPR_COMPMASK_RATE htobe64(((uint64_t)1) << 13)
#define IB_MPR_COMPMASK_PKTLIFETIMESELEC htobe64(((uint64_t)1) << 14)
#define IB_MPR_COMPMASK_PKTLIFETIME htobe64(((uint64_t)1) << 15)
#define IB_MPR_COMPMASK_SERVICEID_MSB htobe64(((uint64_t)1) << 16)
#define IB_MPR_COMPMASK_INDEPSELEC htobe64(((uint64_t)1) << 17)
#define IB_MPR_COMPMASK_RESV3 htobe64(((uint64_t)1) << 18)
#define IB_MPR_COMPMASK_SGIDCOUNT htobe64(((uint64_t)1) << 19)
#define IB_MPR_COMPMASK_DGIDCOUNT htobe64(((uint64_t)1) << 20)
#define IB_MPR_COMPMASK_SERVICEID_LSB htobe64(((uint64_t)1) << 21)
#define IB_SMIR_COMPMASK_LID htobe64(((uint64_t)1) << 0)
#define IB_SMIR_COMPMASK_RESV0 htobe64(((uint64_t)1) << 1)
#define IB_SMIR_COMPMASK_GUID htobe64(((uint64_t)1) << 2)
#define IB_SMIR_COMPMASK_SMKEY htobe64(((uint64_t)1) << 3)
#define IB_SMIR_COMPMASK_ACTCOUNT htobe64(((uint64_t)1) << 4)
#define IB_SMIR_COMPMASK_PRIORITY htobe64(((uint64_t)1) << 5)
#define IB_SMIR_COMPMASK_SMSTATE htobe64(((uint64_t)1) << 6)
#define IB_IIR_COMPMASK_SUBSCRIBERGID htobe64(((uint64_t)1) << 0)
#define IB_IIR_COMPMASK_ENUM htobe64(((uint64_t)1) << 1)
#define IB_IIR_COMPMASK_RESV0 htobe64(((uint64_t)1) << 2)
#define IB_IIR_COMPMASK_GID htobe64(((uint64_t)1) << 3)
#define IB_IIR_COMPMASK_LIDRANGEBEGIN htobe64(((uint64_t)1) << 4)
#define IB_IIR_COMPMASK_LIDRANGEEND htobe64(((uint64_t)1) << 5)
#define IB_IIR_COMPMASK_RESV1 htobe64(((uint64_t)1) << 6)
#define IB_IIR_COMPMASK_ISGENERIC htobe64(((uint64_t)1) << 7)
#define IB_IIR_COMPMASK_SUBSCRIBE htobe64(((uint64_t)1) << 8)
#define IB_IIR_COMPMASK_TYPE htobe64(((uint64_t)1) << 9)
#define IB_IIR_COMPMASK_TRAPNUMB htobe64(((uint64_t)1) << 10)
#define IB_IIR_COMPMASK_DEVICEID htobe64(((uint64_t)1) << 10)
#define IB_IIR_COMPMASK_QPN htobe64(((uint64_t)1) << 11)
#define IB_IIR_COMPMASK_RESV2 htobe64(((uint64_t)1) << 12)
#define IB_IIR_COMPMASK_RESPTIME htobe64(((uint64_t)1) << 13)
#define IB_IIR_COMPMASK_RESV3 htobe64(((uint64_t)1) << 14)
#define IB_IIR_COMPMASK_PRODTYPE htobe64(((uint64_t)1) << 15)
#define IB_IIR_COMPMASK_VENDID htobe64(((uint64_t)1) << 15)
#define IB_CLASS_CAP_TRAP 0x0001
#define IB_CLASS_CAP_GETSET 0x0002
#define IB_CLASS_CAP_CAPMASK2 0x0004
#define IB_CLASS_ENH_PORT0_CC_MASK 0x0100
#define IB_CLASS_RESP_TIME_MASK 0x1F
#define IB_CLASS_CAPMASK2_SHIFT 5
typedef struct {
	uint8_t base_ver;
	uint8_t class_ver;
	__be16 cap_mask;
	__be32 cap_mask2_resp_time;
	ib_gid_t redir_gid;
	__be32 redir_tc_sl_fl;
	__be16 redir_lid;
	__be16 redir_pkey;
	__be32 redir_qp;
	__be32 redir_qkey;
	ib_gid_t trap_gid;
	__be32 trap_tc_sl_fl;
	__be16 trap_lid;
	__be16 trap_pkey;
	__be32 trap_hop_qp;
	__be32 trap_qkey;
} __attribute__((packed)) ib_class_port_info_t;
#define IB_PM_ALL_PORT_SELECT htobe16(1 << 8)
#define IB_PM_EXT_WIDTH_SUPPORTED htobe16(1 << 9)
#define IB_PM_EXT_WIDTH_NOIETF_SUP htobe16(1 << 10)
#define IB_PM_SAMPLES_ONLY_SUP htobe16(1 << 11)
#define IB_PM_PC_XMIT_WAIT_SUP htobe16(1 << 12)
#define IS_PM_INH_LMTD_PKEY_MC_CONSTR_ERR htobe16(1 << 13)
#define IS_PM_RSFEC_COUNTERS_SUP htobe16(1 << 14)
#define IB_PM_IS_QP1_DROP_SUP htobe16(1 << 15)
#define IB_PM_IS_PM_KEY_SUPPORTED htobe32(1 << 0)
#define IB_PM_IS_ADDL_PORT_CTRS_EXT_SUP htobe32(1 << 1)
typedef struct {
	__be64 guid;
	__be64 sm_key;
	__be32 act_count;
	uint8_t pri_state;
} __attribute__((packed)) ib_sm_info_t;
typedef struct {
	uint8_t base_ver;
	uint8_t mgmt_class;
	uint8_t class_ver;
	uint8_t method;
	__be16 status;
	__be16 class_spec;
	__be64 trans_id;
	__be16 attr_id;
	__be16 resv;
	__be32 attr_mod;
} __attribute__((packed)) ib_mad_t;
typedef struct {
	ib_mad_t common_hdr;
	uint8_t rmpp_version;
	uint8_t rmpp_type;
	uint8_t rmpp_flags;
	uint8_t rmpp_status;
	__be32 seg_num;
	__be32 paylen_newwin;
} __attribute__((packed)) ib_rmpp_mad_t;
#define IB_RMPP_TYPE_DATA 1
#define IB_RMPP_TYPE_ACK 2
#define IB_RMPP_TYPE_STOP 3
#define IB_RMPP_TYPE_ABORT 4
#define IB_RMPP_NO_RESP_TIME 0x1F
#define IB_RMPP_FLAG_ACTIVE 0x01
#define IB_RMPP_FLAG_FIRST 0x02
#define IB_RMPP_FLAG_LAST 0x04
#define IB_RMPP_STATUS_SUCCESS 0
#define IB_RMPP_STATUS_RESX 1
#define IB_RMPP_STATUS_T2L 118
#define IB_RMPP_STATUS_BAD_LEN 119
#define IB_RMPP_STATUS_BAD_SEG 120
#define IB_RMPP_STATUS_BADT 121
#define IB_RMPP_STATUS_W2S 122
#define IB_RMPP_STATUS_S2B 123
#define IB_RMPP_STATUS_BAD_STATUS 124
#define IB_RMPP_STATUS_UNV 125
#define IB_RMPP_STATUS_TMR 126
#define IB_RMPP_STATUS_UNSPEC 127
#define IB_SMP_DIRECTION_HO 0x8000
#define IB_SMP_DIRECTION htobe16(IB_SMP_DIRECTION_HO)
#define IB_SMP_STATUS_MASK_HO 0x7FFF
#define IB_SMP_STATUS_MASK htobe16(IB_SMP_STATUS_MASK_HO)
#define IB_SMP_DATA_SIZE 64
typedef struct {
	uint8_t base_ver;
	uint8_t mgmt_class;
	uint8_t class_ver;
	uint8_t method;
	__be16 status;
	uint8_t hop_ptr;
	uint8_t hop_count;
	__be64 trans_id;
	__be16 attr_id;
	__be16 resv;
	__be32 attr_mod;
	__be64 m_key;
	__be16 dr_slid;
	__be16 dr_dlid;
	uint32_t resv1[7];
	uint8_t data[IB_SMP_DATA_SIZE];
	uint8_t initial_path[IB_SUBNET_PATH_HOPS_MAX];
	uint8_t return_path[IB_SUBNET_PATH_HOPS_MAX];
} __attribute__((packed)) ib_smp_t;
typedef struct {
	uint8_t base_version;
	uint8_t class_version;
	uint8_t node_type;
	uint8_t num_ports;
	__be64 sys_guid;
	__be64 node_guid;
	__be64 port_guid;
	__be16 partition_cap;
	__be16 device_id;
	__be32 revision;
	__be32 port_num_vendor_id;
} __attribute__((packed)) ib_node_info_t;
#define IB_SA_DATA_SIZE 200
typedef struct {
	uint8_t base_ver;
	uint8_t mgmt_class;
	uint8_t class_ver;
	uint8_t method;
	__be16 status;
	__be16 resv;
	__be64 trans_id;
	__be16 attr_id;
	__be16 resv1;
	__be32 attr_mod;
	uint8_t rmpp_version;
	uint8_t rmpp_type;
	uint8_t rmpp_flags;
	uint8_t rmpp_status;
	__be32 seg_num;
	__be32 paylen_newwin;
	__be64 sm_key;
	__be16 attr_offset;
	__be16 resv3;
	__be64 comp_mask;
	uint8_t data[IB_SA_DATA_SIZE];
} __attribute__((packed)) ib_sa_mad_t;
#define IB_NODE_INFO_PORT_NUM_MASK htobe32(0xFF000000)
#define IB_NODE_INFO_VEND_ID_MASK htobe32(0x00FFFFFF)
#define IB_NODE_DESCRIPTION_SIZE 64
typedef struct {
	// Node String is an array of UTF-8 characters
	// that describe the node in text format
	// Note that this string is NOT NULL TERMINATED!
	uint8_t description[IB_NODE_DESCRIPTION_SIZE];
} __attribute__((packed)) ib_node_desc_t;
typedef struct {
	__be16 lid;
	__be16 resv;
	ib_node_info_t node_info;
	ib_node_desc_t node_desc;
	uint8_t pad[4];
} __attribute__((packed)) ib_node_record_t;
typedef struct {
	__be64 m_key;
	__be64 subnet_prefix;
	__be16 base_lid;
	__be16 master_sm_base_lid;
	__be32 capability_mask;
	__be16 diag_code;
	__be16 m_key_lease_period;
	uint8_t local_port_num;
	uint8_t link_width_enabled;
	uint8_t link_width_supported;
	uint8_t link_width_active;
	uint8_t state_info1; /* LinkSpeedSupported and PortState */
	uint8_t state_info2; /* PortPhysState and LinkDownDefaultState */
	uint8_t mkey_lmc; /* M_KeyProtectBits and LMC */
	uint8_t link_speed; /* LinkSpeedEnabled and LinkSpeedActive */
	uint8_t mtu_smsl;
	uint8_t vl_cap; /* VLCap and InitType */
	uint8_t vl_high_limit;
	uint8_t vl_arb_high_cap;
	uint8_t vl_arb_low_cap;
	uint8_t mtu_cap;
	uint8_t vl_stall_life;
	uint8_t vl_enforce;
	__be16 m_key_violations;
	__be16 p_key_violations;
	__be16 q_key_violations;
	uint8_t guid_cap;
	uint8_t subnet_timeout; /* cli_rereg(1b), mcast_pkey_trap_suppr(2b), timeout(5b) */
	uint8_t resp_time_value; /* reserv(3b), rtv(5b) */
	uint8_t error_threshold; /* local phy errors(4b), overrun errors(4b) */
	__be16 max_credit_hint;
	__be32 link_rt_latency; /* reserv(8b), link round trip lat(24b) */
	__be16 capability_mask2;
	uint8_t link_speed_ext; /* LinkSpeedExtActive and LinkSpeedExtSupported */
	uint8_t link_speed_ext_enabled; /* reserv(3b), LinkSpeedExtEnabled(5b) */
} __attribute__((packed)) ib_port_info_t;
#define IB_PORT_STATE_MASK 0x0F
#define IB_PORT_LMC_MASK 0x07
#define IB_PORT_LMC_MAX 0x07
#define IB_PORT_MPB_MASK 0xC0
#define IB_PORT_MPB_SHIFT 6
#define IB_PORT_LINK_SPEED_SHIFT 4
#define IB_PORT_LINK_SPEED_SUPPORTED_MASK 0xF0
#define IB_PORT_LINK_SPEED_ACTIVE_MASK 0xF0
#define IB_PORT_LINK_SPEED_ENABLED_MASK 0x0F
#define IB_PORT_PHYS_STATE_MASK 0xF0
#define IB_PORT_PHYS_STATE_SHIFT 4
#define IB_PORT_PHYS_STATE_NO_CHANGE 0
#define IB_PORT_PHYS_STATE_SLEEP 1
#define IB_PORT_PHYS_STATE_POLLING 2
#define IB_PORT_PHYS_STATE_DISABLED 3
#define IB_PORT_PHYS_STATE_PORTCONFTRAIN 4
#define IB_PORT_PHYS_STATE_LINKUP 5
#define IB_PORT_PHYS_STATE_LINKERRRECOVER 6
#define IB_PORT_PHYS_STATE_PHYTEST 7
#define IB_PORT_LNKDWNDFTSTATE_MASK 0x0F
#define IB_PORT_CAP_RESV0 htobe32(0x00000001)
#define IB_PORT_CAP_IS_SM htobe32(0x00000002)
#define IB_PORT_CAP_HAS_NOTICE htobe32(0x00000004)
#define IB_PORT_CAP_HAS_TRAP htobe32(0x00000008)
#define IB_PORT_CAP_HAS_IPD htobe32(0x00000010)
#define IB_PORT_CAP_HAS_AUTO_MIG htobe32(0x00000020)
#define IB_PORT_CAP_HAS_SL_MAP htobe32(0x00000040)
#define IB_PORT_CAP_HAS_NV_MKEY htobe32(0x00000080)
#define IB_PORT_CAP_HAS_NV_PKEY htobe32(0x00000100)
#define IB_PORT_CAP_HAS_LED_INFO htobe32(0x00000200)
#define IB_PORT_CAP_SM_DISAB htobe32(0x00000400)
#define IB_PORT_CAP_HAS_SYS_IMG_GUID htobe32(0x00000800)
#define IB_PORT_CAP_HAS_PKEY_SW_EXT_PORT_TRAP htobe32(0x00001000)
#define IB_PORT_CAP_HAS_CABLE_INFO htobe32(0x00002000)
#define IB_PORT_CAP_HAS_EXT_SPEEDS htobe32(0x00004000)
#define IB_PORT_CAP_HAS_CAP_MASK2 htobe32(0x00008000)
#define IB_PORT_CAP_HAS_COM_MGT htobe32(0x00010000)
#define IB_PORT_CAP_HAS_SNMP htobe32(0x00020000)
#define IB_PORT_CAP_REINIT htobe32(0x00040000)
#define IB_PORT_CAP_HAS_DEV_MGT htobe32(0x00080000)
#define IB_PORT_CAP_HAS_VEND_CLS htobe32(0x00100000)
#define IB_PORT_CAP_HAS_DR_NTC htobe32(0x00200000)
#define IB_PORT_CAP_HAS_CAP_NTC htobe32(0x00400000)
#define IB_PORT_CAP_HAS_BM htobe32(0x00800000)
#define IB_PORT_CAP_HAS_LINK_RT_LATENCY htobe32(0x01000000)
#define IB_PORT_CAP_HAS_CLIENT_REREG htobe32(0x02000000)
#define IB_PORT_CAP_HAS_OTHER_LOCAL_CHANGES_NTC htobe32(0x04000000)
#define IB_PORT_CAP_HAS_LINK_SPEED_WIDTH_PAIRS_TBL htobe32(0x08000000)
#define IB_PORT_CAP_HAS_VEND_MADS htobe32(0x10000000)
#define IB_PORT_CAP_HAS_MCAST_PKEY_TRAP_SUPPRESS htobe32(0x20000000)
#define IB_PORT_CAP_HAS_MCAST_FDB_TOP htobe32(0x40000000)
#define IB_PORT_CAP_HAS_HIER_INFO htobe32(0x80000000)
#define IB_PORT_CAP2_IS_SET_NODE_DESC_SUPPORTED htobe16(0x0001)
#define IB_PORT_CAP2_IS_PORT_INFO_EXT_SUPPORTED htobe16(0x0002)
#define IB_PORT_CAP2_IS_VIRT_SUPPORTED htobe16(0x0004)
#define IB_PORT_CAP2_IS_SWITCH_PORT_STATE_TBL_SUPP htobe16(0x0008)
#define IB_PORT_CAP2_IS_LINK_WIDTH_2X_SUPPORTED htobe16(0x0010)
#define IB_PORT_CAP2_IS_LINK_SPEED_HDR_SUPPORTED htobe16(0x0020)
typedef struct {
	__be32 cap_mask;
	__be16 fec_mode_active;
	__be16 fdr_fec_mode_sup;
	__be16 fdr_fec_mode_enable;
	__be16 edr_fec_mode_sup;
	__be16 edr_fec_mode_enable;
	__be16 hdr_fec_mode_sup;
	__be16 hdr_fec_mode_enable;
	uint8_t reserved[46];
} __attribute__((packed)) ib_port_info_ext_t;
#define IB_PORT_EXT_NO_FEC_MODE_ACTIVE 0
#define IB_PORT_EXT_FIRE_CODE_FEC_MODE_ACTIVE htobe16(0x0001)
#define IB_PORT_EXT_RS_FEC_MODE_ACTIVE htobe16(0x0002)
#define IB_PORT_EXT_LOW_LATENCY_RS_FEC_MODE_ACTIVE htobe16(0x0003)
#define IB_PORT_EXT_CAP_IS_FEC_MODE_SUPPORTED htobe32(0x00000001)
#define IB_LINK_WIDTH_ACTIVE_1X 1
#define IB_LINK_WIDTH_ACTIVE_4X 2
#define IB_LINK_WIDTH_ACTIVE_8X 4
#define IB_LINK_WIDTH_ACTIVE_12X 8
#define IB_LINK_WIDTH_ACTIVE_2X 16
#define IB_LINK_WIDTH_SET_LWS 255
#define IB_LINK_SPEED_ACTIVE_EXTENDED 0
#define IB_LINK_SPEED_ACTIVE_2_5 1
#define IB_LINK_SPEED_ACTIVE_5 2
#define IB_LINK_SPEED_ACTIVE_10 4
#define IB_LINK_SPEED_SET_LSS 15
#define IB_LINK_SPEED_EXT_ACTIVE_NONE 0
#define IB_LINK_SPEED_EXT_ACTIVE_14 1
#define IB_LINK_SPEED_EXT_ACTIVE_25 2
#define IB_LINK_SPEED_EXT_ACTIVE_50 4
#define IB_LINK_SPEED_EXT_DISABLE 30
#define IB_LINK_SPEED_EXT_SET_LSES 31
#define IB_PATH_RECORD_RATE_2_5_GBS 2
#define IB_PATH_RECORD_RATE_10_GBS 3
#define IB_PATH_RECORD_RATE_30_GBS 4
#define IB_PATH_RECORD_RATE_5_GBS 5
#define IB_PATH_RECORD_RATE_20_GBS 6
#define IB_PATH_RECORD_RATE_40_GBS 7
#define IB_PATH_RECORD_RATE_60_GBS 8
#define IB_PATH_RECORD_RATE_80_GBS 9
#define IB_PATH_RECORD_RATE_120_GBS 10
#define IB_PATH_RECORD_RATE_14_GBS 11
#define IB_PATH_RECORD_RATE_56_GBS 12
#define IB_PATH_RECORD_RATE_112_GBS 13
#define IB_PATH_RECORD_RATE_168_GBS 14
#define IB_PATH_RECORD_RATE_25_GBS 15
#define IB_PATH_RECORD_RATE_100_GBS 16
#define IB_PATH_RECORD_RATE_200_GBS 17
#define IB_PATH_RECORD_RATE_300_GBS 18
#define IB_PATH_RECORD_RATE_28_GBS 19
#define IB_PATH_RECORD_RATE_50_GBS 20
#define IB_PATH_RECORD_RATE_400_GBS 21
#define IB_PATH_RECORD_RATE_600_GBS 22
#define FDR10 0x01
typedef struct {
	uint8_t resvd1[3];
	uint8_t state_change_enable;
	uint8_t resvd2[3];
	uint8_t link_speed_supported;
	uint8_t resvd3[3];
	uint8_t link_speed_enabled;
	uint8_t resvd4[3];
	uint8_t link_speed_active;
	uint8_t resvd5[48];
} __attribute__((packed)) ib_mlnx_ext_port_info_t;
typedef struct {
	__be64 service_id;
	ib_gid_t service_gid;
	__be16 service_pkey;
	__be16 resv;
	__be32 service_lease;
	uint8_t service_key[16];
	uint8_t service_name[64];
	uint8_t service_data8[16];
	__be16 service_data16[8];
	__be32 service_data32[4];
	__be64 service_data64[2];
} __attribute__((packed)) ib_service_record_t;
typedef struct {
	__be16 lid;
	uint8_t port_num;
	uint8_t options;
	ib_port_info_t port_info;
	uint8_t pad[4];
} __attribute__((packed)) ib_portinfo_record_t;
typedef struct {
	__be16 lid;
	uint8_t port_num;
	uint8_t options;
	ib_port_info_ext_t port_info_ext;
} __attribute__((packed)) ib_portinfoext_record_t;
typedef struct {
	__be16 from_lid;
	uint8_t from_port_num;
	uint8_t to_port_num;
	__be16 to_lid;
	uint8_t pad[2];
} __attribute__((packed)) ib_link_record_t;
typedef struct {
	__be16 lid;
	uint16_t resv0;
	ib_sm_info_t sm_info;
	uint8_t pad[7];
} __attribute__((packed)) ib_sminfo_record_t;
typedef struct {
	__be16 lid;
	__be16 block_num;
	uint32_t resv0;
	uint8_t lft[64];
} __attribute__((packed)) ib_lft_record_t;
typedef struct {
	__be16 lid;
	__be16 position_block_num;
	uint32_t resv0;
	__be16 mft[IB_MCAST_BLOCK_SIZE];
} __attribute__((packed)) ib_mft_record_t;
typedef struct {
	__be16 lin_cap;
	__be16 rand_cap;
	__be16 mcast_cap;
	__be16 lin_top;
	uint8_t def_port;
	uint8_t def_mcast_pri_port;
	uint8_t def_mcast_not_port;
	uint8_t life_state;
	__be16 lids_per_port;
	__be16 enforce_cap;
	uint8_t flags;
	uint8_t resvd;
	__be16 mcast_top;
} __attribute__((packed)) ib_switch_info_t;
typedef struct {
	__be16 lid;
	uint16_t resv0;
	ib_switch_info_t switch_info;
} __attribute__((packed)) ib_switch_info_record_t;
#define IB_SWITCH_PSC 0x04
#define GUID_TABLE_MAX_ENTRIES 8
typedef struct {
	__be64 guid[GUID_TABLE_MAX_ENTRIES];
} __attribute__((packed)) ib_guid_info_t;
typedef struct {
	__be16 lid;
	uint8_t block_num;
	uint8_t resv;
	uint32_t reserved;
	ib_guid_info_t guid_info;
} __attribute__((packed)) ib_guidinfo_record_t;
#define IB_MULTIPATH_MAX_GIDS 11
typedef struct {
	__be32 hop_flow_raw;
	uint8_t tclass;
	uint8_t num_path;
	__be16 pkey;
	__be16 qos_class_sl;
	uint8_t mtu;
	uint8_t rate;
	uint8_t pkt_life;
	uint8_t service_id_8msb;
	uint8_t independence; /* formerly resv2 */
	uint8_t sgid_count;
	uint8_t dgid_count;
	uint8_t service_id_56lsb[7];
	ib_gid_t gids[IB_MULTIPATH_MAX_GIDS];
} __attribute__((packed)) ib_multipath_rec_t;
#define IB_NUM_PKEY_ELEMENTS_IN_BLOCK 32
typedef struct {
	__be16 pkey_entry[IB_NUM_PKEY_ELEMENTS_IN_BLOCK];
} ib_pkey_table_t;
typedef struct {
	__be16 lid; // for CA: lid of port, for switch lid of port 0
	__be16 block_num;
	uint8_t port_num; // for switch: port number, for CA: reserved
	uint8_t reserved1;
	uint16_t reserved2;
	ib_pkey_table_t pkey_tbl;
} ib_pkey_table_record_t;
#define IB_DROP_VL 15
#define IB_MAX_NUM_VLS 16
typedef struct {
	uint8_t raw_vl_by_sl[IB_MAX_NUM_VLS / 2];
} __attribute__((packed)) ib_slvl_table_t;
typedef struct {
	__be16 lid; // for CA: lid of port, for switch lid of port 0
	uint8_t in_port_num; // reserved for CAs
	uint8_t out_port_num; // reserved for CAs
	uint32_t resv;
	ib_slvl_table_t slvl_tbl;
} __attribute__((packed)) ib_slvl_table_record_t;
typedef struct {
	uint8_t vl;
	uint8_t weight;
} __attribute__((packed)) ib_vl_arb_element_t;
#define IB_NUM_VL_ARB_ELEMENTS_IN_BLOCK 32
typedef struct {
	ib_vl_arb_element_t vl_entry[IB_NUM_VL_ARB_ELEMENTS_IN_BLOCK];
} __attribute__((packed)) ib_vl_arb_table_t;
typedef struct {
	__be16 lid; // for CA: lid of port, for switch lid of port 0
	uint8_t port_num;
	uint8_t block_num;
	uint32_t reserved;
	ib_vl_arb_table_t vl_arb_tbl;
} __attribute__((packed)) ib_vl_arb_table_record_t;
typedef struct {
	__be32 ver_class_flow;
	__be16 resv1;
	uint8_t resv2;
	uint8_t hop_limit;
	ib_gid_t src_gid;
	ib_gid_t dest_gid;
} __attribute__((packed)) ib_grh_t;
typedef struct {
	ib_gid_t mgid;
	ib_gid_t port_gid;
	__be32 qkey;
	__be16 mlid;
	uint8_t mtu;
	uint8_t tclass;
	__be16 pkey;
	uint8_t rate;
	uint8_t pkt_life;
	__be32 sl_flow_hop;
	uint8_t scope_state;
	uint8_t proxy_join : 1;
	uint8_t reserved[2];
	uint8_t pad[4];
} __attribute__((packed)) ib_member_rec_t;
#define IB_MC_REC_STATE_FULL_MEMBER 0x01
#define IB_MC_REC_STATE_NON_MEMBER 0x02
#define IB_MC_REC_STATE_SEND_ONLY_NON_MEMBER 0x04
#define IB_MC_REC_STATE_SEND_ONLY_FULL_MEMBER 0x08
#define IB_NOTICE_TYPE_FATAL 0x00
#define IB_NOTICE_TYPE_URGENT 0x01
#define IB_NOTICE_TYPE_SECURITY 0x02
#define IB_NOTICE_TYPE_SUBN_MGMT 0x03
#define IB_NOTICE_TYPE_INFO 0x04
#define IB_NOTICE_TYPE_EMPTY 0x7F
#define SM_GID_IN_SERVICE_TRAP 64
#define SM_GID_OUT_OF_SERVICE_TRAP 65
#define SM_MGID_CREATED_TRAP 66
#define SM_MGID_DESTROYED_TRAP 67
#define SM_UNPATH_TRAP 68
#define SM_REPATH_TRAP 69
#define SM_LINK_STATE_CHANGED_TRAP 128
#define SM_LINK_INTEGRITY_THRESHOLD_TRAP 129
#define SM_BUFFER_OVERRUN_THRESHOLD_TRAP 130
#define SM_WATCHDOG_TIMER_EXPIRED_TRAP 131
#define SM_LOCAL_CHANGES_TRAP 144
#define SM_SYS_IMG_GUID_CHANGED_TRAP 145
#define SM_BAD_MKEY_TRAP 256
#define SM_BAD_PKEY_TRAP 257
#define SM_BAD_QKEY_TRAP 258
#define SM_BAD_SWITCH_PKEY_TRAP 259
typedef struct {
	uint8_t generic_type; // 1                1
	union _notice_g_or_v {
		struct _notice_generic // 5                6
		{
			uint8_t prod_type_msb;
			__be16 prod_type_lsb;
			__be16 trap_num;
		} __attribute__((packed)) generic;
		struct _notice_vend {
			uint8_t vend_id_msb;
			__be16 vend_id_lsb;
			__be16 dev_id;
		} __attribute__((packed)) vend;
	} g_or_v;
	__be16 issuer_lid; // 2                 8
	__be16 toggle_count; // 2                 10
	union _data_details // 54                64
	{
		struct _raw_data {
			uint8_t details[54];
		} __attribute__((packed)) raw_data;
		struct _ntc_64_67 {
			uint8_t res[6];
			ib_gid_t gid; // the Node or Multicast Group that came in/out
		} __attribute__((packed)) ntc_64_67;
		struct _ntc_128 {
			__be16 sw_lid; // the sw lid of which link state changed
		} __attribute__((packed)) ntc_128;
		struct _ntc_129_131 {
			__be16 pad;
			__be16 lid; // lid and port number of the violation
			uint8_t port_num;
		} __attribute__((packed)) ntc_129_131;
		struct _ntc_144 {
			__be16 pad1;
			__be16 lid; // lid where change occured
			uint8_t pad2; // reserved
			uint8_t local_changes; // 7b reserved 1b local changes
			__be32 new_cap_mask; // new capability mask
			__be16 change_flgs; // 10b reserved 6b change flags
			__be16 cap_mask2;
		} __attribute__((packed)) ntc_144;
		struct _ntc_145 {
			__be16 pad1;
			__be16 lid; // lid where sys guid changed
			__be16 pad2;
			__be64 new_sys_guid; // new system image guid
		} __attribute__((packed)) ntc_145;
		struct _ntc_256 { // total: 54
			__be16 pad1; // 2
			__be16 lid; // 2
			__be16 dr_slid; // 2
			uint8_t method; // 1
			uint8_t pad2; // 1
			__be16 attr_id; // 2
			__be32 attr_mod; // 4
			__be64 mkey; // 8
			uint8_t pad3; // 1
			uint8_t dr_trunc_hop; // 1
			uint8_t dr_rtn_path[30]; // 30
		} __attribute__((packed)) ntc_256;
		struct _ntc_257_258 // violation of p/q_key // 49
		{
			__be16 pad1; // 2
			__be16 lid1; // 2
			__be16 lid2; // 2
			__be32 key; // 4
			__be32 qp1; // 4b sl, 4b pad, 24b qp1
			__be32 qp2; // 8b pad, 24b qp2
			ib_gid_t gid1; // 16
			ib_gid_t gid2; // 16
		} __attribute__((packed)) ntc_257_258;
		struct _ntc_259 // pkey violation from switch 51
		{
			__be16 data_valid; // 2
			__be16 lid1; // 2
			__be16 lid2; // 2
			__be16 pkey; // 2
			__be32 sl_qp1; // 4b sl, 4b pad, 24b qp1
			__be32 qp2; // 8b pad, 24b qp2
			ib_gid_t gid1; // 16
			ib_gid_t gid2; // 16
			__be16 sw_lid; // 2
			uint8_t port_no; // 1
		} __attribute__((packed)) ntc_259;
		struct _ntc_bkey_259 // bkey violation
		{
			__be16 lidaddr;
			uint8_t method;
			uint8_t reserved;
			__be16 attribute_id;
			__be32 attribute_modifier;
			__be32 qp; // qp is low 24 bits
			__be64 bkey;
			ib_gid_t gid;
		} __attribute__((packed)) ntc_bkey_259;
		struct _ntc_cckey_0 // CC key violation
		{
			__be16 slid; // source LID from offending packet LRH
			uint8_t method; // method, from common MAD header
			uint8_t resv0;
			__be16 attribute_id; // Attribute ID, from common MAD header
			__be16 resv1;
			__be32 attribute_modifier; // Attribute Modif, from common MAD header
			__be32 qp; // 8b pad, 24b dest QP from BTH
			__be64 cc_key; // CC key of the offending packet
			ib_gid_t source_gid; // GID from GRH of the offending packet
			uint8_t padding[14]; // Padding - ignored on read
		} __attribute__((packed)) ntc_cckey_0;
	} data_details;
	ib_gid_t issuer_gid; // 16          80
} __attribute__((packed)) ib_mad_notice_attr_t;
#define TRAP_259_MASK_SL htobe32(0xF0000000)
#define TRAP_259_MASK_QP htobe32(0x00FFFFFF)
#define TRAP_144_MASK_OTHER_LOCAL_CHANGES 0x01
#define TRAP_144_MASK_CAPABILITY_MASK2_CHANGE htobe16(0x0020)
#define TRAP_144_MASK_HIERARCHY_INFO_CHANGE htobe16(0x0010)
#define TRAP_144_MASK_SM_PRIORITY_CHANGE htobe16(0x0008)
#define TRAP_144_MASK_LINK_SPEED_ENABLE_CHANGE htobe16(0x0004)
#define TRAP_144_MASK_LINK_WIDTH_ENABLE_CHANGE htobe16(0x0002)
#define TRAP_144_MASK_NODE_DESCRIPTION_CHANGE htobe16(0x0001)
typedef struct {
	ib_gid_t gid;
	__be16 lid_range_begin;
	__be16 lid_range_end;
	__be16 reserved1;
	uint8_t is_generic;
	uint8_t subscribe;
	__be16 trap_type;
	union _inform_g_or_v {
		struct _inform_generic {
			__be16 trap_num;
			__be32 qpn_resp_time_val;
			uint8_t reserved2;
			uint8_t node_type_msb;
			__be16 node_type_lsb;
		} __attribute__((packed)) generic;
		struct _inform_vend {
			__be16 dev_id;
			__be32 qpn_resp_time_val;
			uint8_t reserved2;
			uint8_t vendor_id_msb;
			__be16 vendor_id_lsb;
		} __attribute__((packed)) vend;
	} __attribute__((packed)) g_or_v;
} __attribute__((packed)) ib_inform_info_t;
typedef struct {
	ib_gid_t subscriber_gid;
	__be16 subscriber_enum;
	uint8_t reserved[6];
	ib_inform_info_t inform_info;
	uint8_t pad[4];
} __attribute__((packed)) ib_inform_info_record_t;
typedef struct {
	ib_mad_t header;
	uint8_t resv[40];
#define IB_PM_DATA_SIZE 192
	uint8_t data[IB_PM_DATA_SIZE];
} __attribute__((packed)) ib_perfmgt_mad_t;
typedef struct {
	uint8_t reserved;
	uint8_t port_select;
	__be16 counter_select;
	__be16 symbol_err_cnt;
	uint8_t link_err_recover;
	uint8_t link_downed;
	__be16 rcv_err;
	__be16 rcv_rem_phys_err;
	__be16 rcv_switch_relay_err;
	__be16 xmit_discards;
	uint8_t xmit_constraint_err;
	uint8_t rcv_constraint_err;
	uint8_t counter_select2;
	uint8_t link_int_buffer_overrun;
	__be16 qp1_dropped;
	__be16 vl15_dropped;
	__be32 xmit_data;
	__be32 rcv_data;
	__be32 xmit_pkts;
	__be32 rcv_pkts;
	__be32 xmit_wait;
} __attribute__((packed)) ib_port_counters_t;
typedef struct {
	uint8_t reserved;
	uint8_t port_select;
	__be16 counter_select;
	__be32 counter_select2;
	__be64 xmit_data;
	__be64 rcv_data;
	__be64 xmit_pkts;
	__be64 rcv_pkts;
	__be64 unicast_xmit_pkts;
	__be64 unicast_rcv_pkts;
	__be64 multicast_xmit_pkts;
	__be64 multicast_rcv_pkts;
	__be64 symbol_err_cnt;
	__be64 link_err_recover;
	__be64 link_downed;
	__be64 rcv_err;
	__be64 rcv_rem_phys_err;
	__be64 rcv_switch_relay_err;
	__be64 xmit_discards;
	__be64 xmit_constraint_err;
	__be64 rcv_constraint_err;
	__be64 link_integrity_err;
	__be64 buffer_overrun;
	__be64 vl15_dropped;
	__be64 xmit_wait;
	__be64 qp1_dropped;
} __attribute__((packed)) ib_port_counters_ext_t;
typedef struct {
	uint8_t op_code;
	uint8_t port_select;
	uint8_t tick;
	uint8_t counter_width; /* 5 bits res : 3bits counter_width */
	__be32 counter_mask; /* 2 bits res : 3 bits counter_mask : 27 bits counter_masks_1to9 */
	__be16 counter_mask_10to14; /* 1 bits res : 15 bits counter_masks_10to14 */
	uint8_t sample_mech;
	uint8_t sample_status; /* 6 bits res : 2 bits sample_status */
	__be64 option_mask;
	__be64 vendor_mask;
	__be32 sample_start;
	__be32 sample_interval;
	__be16 tag;
	__be16 counter_select0;
	__be16 counter_select1;
	__be16 counter_select2;
	__be16 counter_select3;
	__be16 counter_select4;
	__be16 counter_select5;
	__be16 counter_select6;
	__be16 counter_select7;
	__be16 counter_select8;
	__be16 counter_select9;
	__be16 counter_select10;
	__be16 counter_select11;
	__be16 counter_select12;
	__be16 counter_select13;
	__be16 counter_select14;
} __attribute__((packed)) ib_port_samples_control_t;
#define IB_CS_PORT_XMIT_DATA htobe16(0x0001)
#define IB_CS_PORT_RCV_DATA htobe16(0x0002)
#define IB_CS_PORT_XMIT_PKTS htobe16(0x0003)
#define IB_CS_PORT_RCV_PKTS htobe16(0x0004)
#define IB_CS_PORT_XMIT_WAIT htobe16(0x0005)
typedef struct {
	__be16 tag;
	__be16 sample_status; /* 14 bits res : 2 bits sample_status */
	__be32 counter0;
	__be32 counter1;
	__be32 counter2;
	__be32 counter3;
	__be32 counter4;
	__be32 counter5;
	__be32 counter6;
	__be32 counter7;
	__be32 counter8;
	__be32 counter9;
	__be32 counter10;
	__be32 counter11;
	__be32 counter12;
	__be32 counter13;
	__be32 counter14;
} __attribute__((packed)) ib_port_samples_result_t;
typedef struct {
	uint8_t reserved;
	uint8_t port_select;
	__be16 counter_select;
	__be32 port_xmit_data_sl[16];
	uint8_t resv[124];
} __attribute__((packed)) ib_port_xmit_data_sl_t;
typedef struct {
	uint8_t reserved;
	uint8_t port_select;
	__be16 counter_select;
	__be32 port_rcv_data_sl[16];
	uint8_t resv[124];
} __attribute__((packed)) ib_port_rcv_data_sl_t;
typedef struct {
	ib_mad_t header;
	uint8_t resv[40];
#define IB_DM_DATA_SIZE 192
	uint8_t data[IB_DM_DATA_SIZE];
} __attribute__((packed)) ib_dm_mad_t;
typedef struct {
	__be16 change_id;
	uint8_t max_controllers;
	uint8_t diag_rom;
#define IB_DM_CTRL_LIST_SIZE 128
	uint8_t controller_list[IB_DM_CTRL_LIST_SIZE];
#define IOC_NOT_INSTALLED 0x0
#define IOC_INSTALLED 0x1
//              Reserved values                         0x02-0xE
#define SLOT_DOES_NOT_EXIST 0xF
} __attribute__((packed)) ib_iou_info_t;
typedef struct {
	__be64 ioc_guid;
	__be32 vend_id;
	__be32 dev_id;
	__be16 dev_ver;
	__be16 resv2;
	__be32 subsys_vend_id;
	__be32 subsys_id;
	__be16 io_class;
	__be16 io_subclass;
	__be16 protocol;
	__be16 protocol_ver;
	__be32 resv3;
	__be16 send_msg_depth;
	uint8_t resv4;
	uint8_t rdma_read_depth;
	__be32 send_msg_size;
	__be32 rdma_size;
	uint8_t ctrl_ops_cap;
#define CTRL_OPS_CAP_ST 0x01
#define CTRL_OPS_CAP_SF 0x02
#define CTRL_OPS_CAP_RT 0x04
#define CTRL_OPS_CAP_RF 0x08
#define CTRL_OPS_CAP_WT 0x10
#define CTRL_OPS_CAP_WF 0x20
#define CTRL_OPS_CAP_AT 0x40
#define CTRL_OPS_CAP_AF 0x80
	uint8_t resv5;
	uint8_t num_svc_entries;
#define MAX_NUM_SVC_ENTRIES 0xff
	uint8_t resv6[9];
#define CTRL_ID_STRING_LEN 64
	char id_string[CTRL_ID_STRING_LEN];
} __attribute__((packed)) ib_ioc_profile_t;
typedef struct {
#define MAX_SVC_ENTRY_NAME_LEN 40
	char name[MAX_SVC_ENTRY_NAME_LEN];
	__be64 id;
} __attribute__((packed)) ib_svc_entry_t;
typedef struct {
#define SVC_ENTRY_COUNT 4
	ib_svc_entry_t service_entry[SVC_ENTRY_COUNT];
} __attribute__((packed)) ib_svc_entries_t;
typedef struct {
	__be64 module_guid;
	__be64 iou_guid;
	ib_ioc_profile_t ioc_profile;
	__be64 access_key;
	uint16_t initiators_conf;
	uint8_t resv[38];
} __attribute__((packed)) ib_ioc_info_t;
typedef struct {
	bool cm;
	bool snmp;
	bool dev_mgmt;
	bool vend;
	bool sm;
	bool sm_disable;
	bool qkey_ctr;
	bool pkey_ctr;
	bool notice;
	bool trap;
	bool apm;
	bool slmap;
	bool pkey_nvram;
	bool mkey_nvram;
	bool sysguid;
	bool dr_notice;
	bool boot_mgmt;
	bool capm_notice;
	bool reinit;
	bool ledinfo;
	bool port_active;
} ib_port_cap_t;
#define IB_INIT_TYPE_NO_LOAD 0x01
#define IB_INIT_TYPE_PRESERVE_CONTENT 0x02
#define IB_INIT_TYPE_PRESERVE_PRESENCE 0x04
#define IB_INIT_TYPE_DO_NOT_RESUSCITATE 0x08
typedef struct {
	uint8_t port_num;
	uint8_t sl;
	__be16 dlid;
	bool grh_valid;
	ib_grh_t grh;
	uint8_t static_rate;
	uint8_t path_bits;
	struct _av_conn {
		uint8_t path_mtu;
		uint8_t local_ack_timeout;
		uint8_t seq_err_retry_cnt;
		uint8_t rnr_retry_cnt;
	} conn;
} ib_av_attr_t;
#define IB_AC_RDMA_READ 0x00000001
#define IB_AC_RDMA_WRITE 0x00000002
#define IB_AC_ATOMIC 0x00000004
#define IB_AC_LOCAL_WRITE 0x00000008
#define IB_AC_MW_BIND 0x00000010
#define IB_QPS_RESET 0x00000001
#define IB_QPS_INIT 0x00000002
#define IB_QPS_RTR 0x00000004
#define IB_QPS_RTS 0x00000008
#define IB_QPS_SQD 0x00000010
#define IB_QPS_SQD_DRAINING 0x00000030
#define IB_QPS_SQD_DRAINED 0x00000050
#define IB_QPS_SQERR 0x00000080
#define IB_QPS_ERROR 0x00000100
#define IB_QPS_TIME_WAIT 0xDEAD0000
#define IB_MOD_QP_ALTERNATE_AV 0x00000001
#define IB_MOD_QP_PKEY 0x00000002
#define IB_MOD_QP_APM_STATE 0x00000004
#define IB_MOD_QP_PRIMARY_AV 0x00000008
#define IB_MOD_QP_RNR_NAK_TIMEOUT 0x00000010
#define IB_MOD_QP_RESP_RES 0x00000020
#define IB_MOD_QP_INIT_DEPTH 0x00000040
#define IB_MOD_QP_PRIMARY_PORT 0x00000080
#define IB_MOD_QP_ACCESS_CTRL 0x00000100
#define IB_MOD_QP_QKEY 0x00000200
#define IB_MOD_QP_SQ_DEPTH 0x00000400
#define IB_MOD_QP_RQ_DEPTH 0x00000800
#define IB_MOD_QP_CURRENT_STATE 0x00001000
#define IB_MOD_QP_RETRY_CNT 0x00002000
#define IB_MOD_QP_LOCAL_ACK_TIMEOUT 0x00004000
#define IB_MOD_QP_RNR_RETRY_CNT 0x00008000
#define IB_MOD_EEC_ALTERNATE_AV 0x00000001
#define IB_MOD_EEC_PKEY 0x00000002
#define IB_MOD_EEC_APM_STATE 0x00000004
#define IB_MOD_EEC_PRIMARY_AV 0x00000008
#define IB_MOD_EEC_RNR 0x00000010
#define IB_MOD_EEC_RESP_RES 0x00000020
#define IB_MOD_EEC_OUTSTANDING 0x00000040
#define IB_MOD_EEC_PRIMARY_PORT 0x00000080
#define IB_SEND_OPT_IMMEDIATE 0x00000001
#define IB_SEND_OPT_FENCE 0x00000002
#define IB_SEND_OPT_SIGNALED 0x00000004
#define IB_SEND_OPT_SOLICITED 0x00000008
#define IB_SEND_OPT_INLINE 0x00000010
#define IB_SEND_OPT_LOCAL 0x00000020
#define IB_SEND_OPT_VEND_MASK 0xFFFF0000
#define IB_RECV_OPT_IMMEDIATE 0x00000001
#define IB_RECV_OPT_FORWARD 0x00000002
#define IB_RECV_OPT_GRH_VALID 0x00000004
#define IB_RECV_OPT_VEND_MASK 0xFFFF0000
#define IB_CA_MOD_IS_CM_SUPPORTED 0x00000001
#define IB_CA_MOD_IS_SNMP_SUPPORTED 0x00000002
#define IB_CA_MOD_IS_DEV_MGMT_SUPPORTED 0x00000004
#define IB_CA_MOD_IS_VEND_SUPPORTED 0x00000008
#define IB_CA_MOD_IS_SM 0x00000010
#define IB_CA_MOD_IS_SM_DISABLED 0x00000020
#define IB_CA_MOD_QKEY_CTR 0x00000040
#define IB_CA_MOD_PKEY_CTR 0x00000080
#define IB_CA_MOD_IS_NOTICE_SUPPORTED 0x00000100
#define IB_CA_MOD_IS_TRAP_SUPPORTED 0x00000200
#define IB_CA_MOD_IS_APM_SUPPORTED 0x00000400
#define IB_CA_MOD_IS_SLMAP_SUPPORTED 0x00000800
#define IB_CA_MOD_IS_PKEY_NVRAM_SUPPORTED 0x00001000
#define IB_CA_MOD_IS_MKEY_NVRAM_SUPPORTED 0x00002000
#define IB_CA_MOD_IS_SYSGUID_SUPPORTED 0x00004000
#define IB_CA_MOD_IS_DR_NOTICE_SUPPORTED 0x00008000
#define IB_CA_MOD_IS_BOOT_MGMT_SUPPORTED 0x00010000
#define IB_CA_MOD_IS_CAPM_NOTICE_SUPPORTED 0x00020000
#define IB_CA_MOD_IS_REINIT_SUPORTED 0x00040000
#define IB_CA_MOD_IS_LEDINFO_SUPPORTED 0x00080000
#define IB_CA_MOD_SHUTDOWN_PORT 0x00100000
#define IB_CA_MOD_INIT_TYPE_VALUE 0x00200000
#define IB_CA_MOD_SYSTEM_IMAGE_GUID 0x00400000
#define IB_MR_MOD_ADDR 0x00000001
#define IB_MR_MOD_PD 0x00000002
#define IB_MR_MOD_ACCESS 0x00000004
#define IB_SMINFO_ATTR_MOD_HANDOVER htobe32(0x000001)
#define IB_SMINFO_ATTR_MOD_ACKNOWLEDGE htobe32(0x000002)
#define IB_SMINFO_ATTR_MOD_DISABLE htobe32(0x000003)
#define IB_SMINFO_ATTR_MOD_STANDBY htobe32(0x000004)
#define IB_SMINFO_ATTR_MOD_DISCOVER htobe32(0x000005)
#define IB_CC_LOG_DATA_SIZE 32
#define IB_CC_MGT_DATA_SIZE 192
typedef struct {
	ib_mad_t header;
	__be64 cc_key;
	uint8_t log_data[IB_CC_LOG_DATA_SIZE];
	uint8_t mgt_data[IB_CC_MGT_DATA_SIZE];
} __attribute__((packed)) ib_cc_mad_t;
typedef struct {
	uint8_t cong_info;
	uint8_t resv;
	uint8_t ctrl_table_cap;
} __attribute__((packed)) ib_cong_info_t;
typedef struct {
	__be64 cc_key;
	__be16 protect_bit;
	__be16 lease_period;
	__be16 violations;
} __attribute__((packed)) ib_cong_key_info_t;
typedef struct {
	__be16 slid;
	__be16 dlid;
	__be32 sl;
	__be32 time_stamp;
} __attribute__((packed)) ib_cong_log_event_sw_t;
typedef struct {
	__be32 local_qp_resv0;
	__be32 remote_qp_sl_service_type;
	__be16 remote_lid;
	__be16 resv1;
	__be32 time_stamp;
} __attribute__((packed)) ib_cong_log_event_ca_t;
typedef struct {
	uint8_t log_type;
	union _log_details {
		struct _log_sw {
			uint8_t cong_flags;
			__be16 event_counter;
			__be32 time_stamp;
			uint8_t port_map[32];
			ib_cong_log_event_sw_t entry_list[15];
		} __attribute__((packed)) log_sw;

		struct _log_ca {
			uint8_t cong_flags;
			__be16 event_counter;
			__be16 event_map;
			__be16 resv;
			__be32 time_stamp;
			ib_cong_log_event_ca_t log_event[13];
		} __attribute__((packed)) log_ca;

	} log_details;
} __attribute__((packed)) ib_cong_log_t;
#define IB_CC_PORT_MASK_DATA_SIZE 32
typedef struct {
	__be32 control_map;
	uint8_t victim_mask[IB_CC_PORT_MASK_DATA_SIZE];
	uint8_t credit_mask[IB_CC_PORT_MASK_DATA_SIZE];
	uint8_t threshold_resv;
	uint8_t packet_size;
	__be16 cs_threshold_resv;
	__be16 cs_return_delay;
	__be16 marking_rate;
} __attribute__((packed)) ib_sw_cong_setting_t;
typedef struct {
	uint8_t valid_ctrl_type_res_threshold;
	uint8_t packet_size;
	__be16 cong_param;
} __attribute__((packed)) ib_sw_port_cong_setting_element_t;
#define IB_CC_SW_PORT_SETTING_ELEMENTS 32
typedef struct {
	ib_sw_port_cong_setting_element_t block[IB_CC_SW_PORT_SETTING_ELEMENTS];
} __attribute__((packed)) ib_sw_port_cong_setting_t;
typedef struct {
	__be16 ccti_timer;
	uint8_t ccti_increase;
	uint8_t trigger_threshold;
	uint8_t ccti_min;
	uint8_t resv0;
	__be16 resv1;
} __attribute__((packed)) ib_ca_cong_entry_t;
#define IB_CA_CONG_ENTRY_DATA_SIZE 16
typedef struct {
	__be16 port_control;
	__be16 control_map;
	ib_ca_cong_entry_t entry_list[IB_CA_CONG_ENTRY_DATA_SIZE];
} __attribute__((packed)) ib_ca_cong_setting_t;
typedef struct {
	__be16 shift_multiplier;
} __attribute__((packed)) ib_cc_tbl_entry_t;
#define IB_CC_TBL_ENTRY_LIST_MAX 64
typedef struct {
	__be16 ccti_limit;
	__be16 resv;
	ib_cc_tbl_entry_t entry_list[IB_CC_TBL_ENTRY_LIST_MAX];
} __attribute__((packed)) ib_cc_tbl_t;
typedef struct {
	__be32 value;
} __attribute__((packed)) ib_time_stamp_t;

#define IB_PM_PC_XMIT_WAIT_SUP htobe16(1 << 12)
#define IS_PM_RSFEC_COUNTERS_SUP htobe16(1 << 14)
#define IB_PM_IS_QP1_DROP_SUP htobe16(1 << 15)
#define IB_PM_IS_ADDL_PORT_CTRS_EXT_SUP htobe32(1 << 1)
#define IB_PORT_CAP2_IS_PORT_INFO_EXT_SUPPORTED htobe16(0x0002)
#define IB_PORT_EXT_NO_FEC_MODE_ACTIVE 0
#define IB_PORT_EXT_FIRE_CODE_FEC_MODE_ACTIVE htobe16(0x0001)
#define IB_PORT_EXT_RS_FEC_MODE_ACTIVE htobe16(0x0002)
#define IB_PORT_EXT_LOW_LATENCY_RS_FEC_MODE_ACTIVE htobe16(0x0003)
#define IB_PORT_EXT_RS_FEC2_MODE_ACTIVE htobe16(0x0004)
#define IB_PORT_EXT_CAP_IS_FEC_MODE_SUPPORTED htobe32(0x00000001)

static inline uint32_t ib_class_cap_mask2(const ib_class_port_info_t *p_cpi)
{
	return (be32toh(p_cpi->cap_mask2_resp_time) >> IB_CLASS_CAPMASK2_SHIFT);
}

static inline uint8_t ib_class_resp_time_val(ib_class_port_info_t *p_cpi)
{
	return (uint8_t)(be32toh(p_cpi->cap_mask2_resp_time) &
			 IB_CLASS_RESP_TIME_MASK);
}

static inline const char *ib_get_node_type_str(uint8_t node_type)
{
	static const char *const __ib_node_type_str[] = {
		"UNKNOWN",
		"Channel Adapter",
		"Switch",
		"Router",
	};

	if (node_type > IB_NODE_TYPE_ROUTER)
		node_type = 0;
	return (__ib_node_type_str[node_type]);
}

static inline __be32 ib_inform_info_get_prod_type(const ib_inform_info_t *p_inf)
{
	uint32_t nt;

	nt = be16toh(p_inf->g_or_v.generic.node_type_lsb) |
	     (p_inf->g_or_v.generic.node_type_msb << 16);
	return htobe32(nt);
}

static inline void
ib_inform_info_get_qpn_resp_time(const __be32 qpn_resp_time_val, __be32 *p_qpn,
				 uint8_t *p_resp_time_val)
{
	uint32_t tmp = be32toh(qpn_resp_time_val);

	if (p_qpn)
		*p_qpn = htobe32((tmp & 0xffffff00) >> 8);
	if (p_resp_time_val)
		*p_resp_time_val = (uint8_t)(tmp & 0x0000001f);
}

static inline void ib_member_get_scope_state(const uint8_t scope_state,
					     uint8_t *p_scope, uint8_t *p_state)
{
	uint8_t tmp_scope_state;

	if (p_state)
		*p_state = (uint8_t)(scope_state & 0x0f);

	tmp_scope_state = scope_state >> 4;

	if (p_scope)
		*p_scope = (uint8_t)(tmp_scope_state & 0x0f);
}

static inline void ib_member_get_sl_flow_hop(const __be32 sl_flow_hop,
					     uint8_t *p_sl,
					     uint32_t *p_flow_lbl,
					     uint8_t *p_hop)
{
	uint32_t tmp;

	tmp = be32toh(sl_flow_hop);
	if (p_hop)
		*p_hop = (uint8_t)tmp;
	tmp >>= 8;

	if (p_flow_lbl)
		*p_flow_lbl = (uint32_t)(tmp & 0xfffff);
	tmp >>= 20;

	if (p_sl)
		*p_sl = (uint8_t)tmp;
}

static inline __be32 ib_member_set_sl_flow_hop(const uint8_t sl,
					       const uint32_t flow_label,
					       const uint8_t hop_limit)
{
	uint32_t tmp;

	tmp = (sl << 28) | ((flow_label & 0xfffff) << 8) | hop_limit;
	return htobe32(tmp);
}

static inline __be32 ib_node_info_get_vendor_id(const ib_node_info_t *p_ni)
{
	return ((__be32)(p_ni->port_num_vendor_id & IB_NODE_INFO_VEND_ID_MASK));
}

static inline uint8_t
ib_node_info_get_local_port_num(const ib_node_info_t *p_ni)
{
	return be32toh(p_ni->port_num_vendor_id & IB_NODE_INFO_PORT_NUM_MASK) >>
	       24;
}

static inline uint16_t ib_path_rec_qos_class(const ib_path_rec_t *p_rec)
{
	return (be16toh(p_rec->qos_class_sl) >> 4);
}

static inline void ib_path_rec_set_qos_class(ib_path_rec_t *p_rec,
					     const uint16_t qos_class)
{
	p_rec->qos_class_sl =
		(p_rec->qos_class_sl & htobe16(IB_PATH_REC_SL_MASK)) |
		htobe16(qos_class << 4);
}

static inline uint8_t ib_path_rec_sl(const ib_path_rec_t *p_rec)
{
	return (uint8_t)(be16toh(p_rec->qos_class_sl) & IB_PATH_REC_SL_MASK);
}

static inline uint8_t ib_slvl_table_get(const ib_slvl_table_t *p_slvl_tbl,
					uint8_t sl_index)
{
	uint8_t idx = sl_index / 2;
	assert(sl_index <= 15);

	if (sl_index % 2)
		/* this is an odd sl. Need to return the ls bits. */
		return (p_slvl_tbl->raw_vl_by_sl[idx] & 0x0F);
	else
		/* this is an even sl. Need to return the ms bits. */
		return ((p_slvl_tbl->raw_vl_by_sl[idx] & 0xF0) >> 4);
}

static inline uint8_t ib_sminfo_get_priority(const ib_sm_info_t *p_smi)
{
	return ((uint8_t)((p_smi->pri_state & 0xF0) >> 4));
}

static inline uint8_t ib_sminfo_get_state(const ib_sm_info_t *p_smi)
{
	return ((uint8_t)(p_smi->pri_state & 0x0F));
}

#endif
