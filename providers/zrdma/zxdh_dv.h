/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2024 ZTE Corporation.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
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
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef _ZXDH_DV_H_
#define _ZXDH_DV_H_

#include <stdio.h>
#include <stdbool.h>
#include <linux/types.h> /* For the __be64 type */
#include <sys/types.h>
#include <endian.h>
#if defined(__SSE3__)
#include <limits.h>
#include <emmintrin.h>
#include <tmmintrin.h>
#endif /* defined(__SSE3__) */

#include <infiniband/verbs.h>
#include <infiniband/tm_types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum switch_status {
	SWITCH_CLOSE = 0,
	SWITCH_OPEN = 1,
	SWITCH_ERROR,
};

enum zxdh_qp_reset_qp_code {
	ZXDH_RESET_RETRY_TX_ITEM_FLAG = 1,
};

enum zxdh_qp_modify_qpc_mask {
	ZXDH_RETRY_CQE_SQ_OPCODE = 1 << 0,
	ZXDH_ERR_FLAG_SET = 1 << 1,
	ZXDH_PACKAGE_ERR_FLAG = 1 << 2,
	ZXDH_TX_LAST_ACK_PSN = 1 << 3,
	ZXDH_TX_LAST_ACK_WQE_OFFSET_SET = 1 << 4,
	ZXDH_TX_READ_RETRY_FLAG_SET = 1 << 5,
	ZXDH_TX_RDWQE_PYLD_LENGTH = 1 << 6,
	ZXDH_TX_RECV_READ_FLAG_SET = 1 << 7,
	ZXDH_TX_RD_MSG_LOSS_ERR_FLAG_SET = 1 << 8,
};

struct zxdh_rdma_qpc {
	uint8_t retry_flag;
	uint8_t rnr_retry_flag;
	uint8_t read_retry_flag;
	uint8_t cur_retry_count;
	uint8_t retry_cqe_sq_opcode;
	uint8_t err_flag;
	uint8_t ack_err_flag;
	uint8_t package_err_flag;
	uint8_t recv_err_flag;
	uint32_t tx_last_ack_psn;
	uint8_t retry_count;
};

struct zxdh_rdma_cap_pa {
	__u64 cap_pa_node0;
	__u64 cap_pa_node1;
};

#define CAP_NODE_NUM 2
#define NODE1 1
#define NODE0 0
#define EN_32bit_GROUP_NUM 16
#define BIT_O_31 0
#define BIT_32_63 1
#define BIT_64_95 2
#define BIT_96_127 3
#define BIT_128_159 4
#define BIT_160_191 5
#define BIT_192_223 6
#define BIT_224_255 7
#define BIT_256_287 8
#define BIT_288_319 9
#define BIT_320_351 10
#define BIT_352_383 11
#define BIT_384_415 12
#define BIT_416_447 13
#define BIT_448_479 14
#define BIT_480_511 15
#define CAP_TX 1
#define CAP_RX 2
#define FREE_TYPE_NONE 0
#define FREE_TYPE_MP 1
#define FREE_TYPE_TX 2
#define FREE_TYPE_RX 3
#define FREE_TYPE_IOVA 4
#define FREE_TYPE_HW_OBJ_DATA 5

struct zxdh_cap_cfg {
	uint8_t cap_position;
	uint64_t size;
	uint32_t channel_select[CAP_NODE_NUM];
	uint32_t channel_open[CAP_NODE_NUM];
	uint32_t node_choose[CAP_NODE_NUM];
	uint32_t node_select[CAP_NODE_NUM];
	uint32_t compare_bit_en[EN_32bit_GROUP_NUM][CAP_NODE_NUM];
	uint32_t compare_data[EN_32bit_GROUP_NUM][CAP_NODE_NUM];
	uint32_t rdma_time_wrl2d[CAP_NODE_NUM];
	uint32_t extra[CAP_NODE_NUM][EN_32bit_GROUP_NUM];
	uint32_t cap_data_start_cap;
};

#define MAX_CAP_QPS 4
struct zxdh_mp_cap_cfg {
	bool cap_use_l2d;
	uint32_t qpn[MAX_CAP_QPS];
	uint8_t qpn_num;
};

enum {
	MCODE_TYPE_DCQCN = 1,
	MCODE_TYPE_RTT,
	MCODE_TYPE_BASERTT,
	MCODE_TYPE_PID,
	MCODE_TYPE_WUMENG = 6,
};
struct zxdh_mp_cap_gqp {
	uint8_t mcode_type;
	uint8_t gqp_num;
	uint16_t gqpid[MAX_CAP_QPS];
	uint64_t cap_pa;
};

struct zxdh_cap_gqp {
	uint16_t gqpid[MAX_CAP_QPS];
	uint8_t gqp_num;
};

#define MAX_ACTIVE_GQP_NUM 16
struct zxdh_active_vhca_gqps {
	uint16_t vhca_id;
	uint16_t gqp_id[MAX_ACTIVE_GQP_NUM];
	uint8_t gqp_num;
};

enum zxdh_context_type {
	ZXDH_RX_READ_QPC = 1,
	ZXDH_TX_READ_QPC,
	ZXDH_READ_CQC,
	ZXDH_READ_CEQC,
	ZXDH_READ_AEQC,
	ZXDH_RX_READ_SRQC,
	ZXDH_READ_MRTE,
};

struct zxdh_context_req {
	enum zxdh_context_type type;
	__u32 resource_id;
};

#define MAX_CONTEXT_SIZE 22
struct zxdh_context_resp {
	__u64 context_info[MAX_CONTEXT_SIZE];
	__u8 context_size;
};

enum zxdh_data_type {
	ZXDH_PATH_SELECT_TYPE_CACHE = 1,
	ZXDH_PATH_SELECT_TYPE_INDICATE,
};

enum zxdh_context_type_ex {
	DATA_TYPE_PBLE_MR = 0,
	DATA_TYPE_PBLE_SQ_RQ_SRQP_SRQ_CQ_CEQ_AEQ = 1,
	DATA_TYPE_AH = 3,
	DATA_TYPE_IRD = 4,
	DATA_TYPE_TX_WINDOW = 5,
	DATA_TYPE_SQ = 11,
	DATA_TYPE_RQ = 13,
	DATA_TYPE_RQ_DOORBELL_SHADOW = 14,
	DATA_TYPE_SRQP = 15,
	DATA_TYPE_SRQ = 16,
	DATA_TYPE_SRQ_DOORBELL_SHADOW = 17,
	DATA_TYPE_CQ = 18,
	DATA_TYPE_CQ_DOORBELL_SHADOW = 19,
	DATA_TYPE_CEQ = 20,
	DATA_TYPE_AEQ = 21,
};

enum zxdh_error_code_const {
	ZXDH_NOT_SUPPORT_OBJECT_ID = 100,
	ZXDH_DMA_MEMORY_OVER_2M = 101,
	ZXDH_DMA_READ_NOT_32_ALIGN = 102,
	ZXDH_CACHE_ID_CHECK_ERROR = 103,
	ZXDH_ENTRY_IDX_ERROR = 104,
	ZXDH_PBLE_ADDRESSING_ONLY_SUPPORTS_OBJECT_NUMBER_1 = 105,
	ZXDH_NOT_SUPPORT_TWO_LEVEL_PBLE_CODE = 106,
	ZXDH_NOT_SUPPORT_VIRTUAL_ADDRESS = 107,
	ZXDH_DATA_ENTRY_IDX_OVER_LIMIT = 108,
	ZXDH_QUEUE_ID_ERROR = 109,
	/* Must be last entry*/
	ZXDH_CUSTOM_ERROR_CODE,
};

struct zxdh_get_object_data_req {
	__u32 queue_id;
	__u8 object_id;
	__u32 entry_idx;
	__u8 object_num;
};

struct zxdh_get_object_data_resp {
	__u64 object_mmap_offset;
	__u32 length;
	__u32 object_size;
	__u64 srqp_aligned_offset;
	__u16 vhca_id;
	__u8 route_id;
};

enum zxdh_object_qp_type_const {
	ZXDH_QP_TYPE_QP = 1,
	ZXDH_QP_TYPE_SRQ,
	ZXDH_QP_TYPE_CQ,
	ZXDH_QP_TYPE_CEQ,
	ZXDH_QP_TYPE_AEQ,
};

struct zxdh_object_data_print {
	int object_id;
	const char *object_type;
	int src_path_select_type;
	__u32 length;
	__u32 queue_id;
	int qp_type;
};

#define ZXDH_L2D_MPCAP_BUFF_SIZE 0x14000u
#define ZXDH_HOST_DATA_CAP_MEM_SIZE (1024 * 1024 * 1024)

struct zxdh_cc_basic_info {
	__u32 active_gqp_cnt;
	__u16 active_vhca_sq_cnt;
	__u16 active_vhca_read_cnt;
	__u16 active_vhca_ack_cnt;
	__u16 active_qp_sq_cur_cnt;
	__u16 active_qp_rq_cur_cnt;
	__u16 task_prefetch_recv_com_cnt;
	__u64 tx_pkt_cnt;
	__u64 rx_pkt_cnt;
	__u16 flight_pkt_cnt;
	__u16 retry_timeout_cnt;
	__u16 retry_read_cnt;
	__u16 retry_rnr_cnt;
	__u16 retry_nak_cnt;
	__u16 drop_read_msg_cnt;
	__u32 tx_pkt_cnp_cnt;
	__u32 rx_pkt_cnp_cnt;
	__u32 tx_pkt_rtt_t1_cnt;
	__u32 rx_pkt_rtt_t2_cnt;
	__u32 tx_pkt_rtt_t4_cnt;
	__u32 rx_pkt_rtt_t5_cnt;
	__u16 limit_tx_sq_cnt;
	__u16 limit_tx_read_ack_cnt;
	__u32 backpres_tx_pfc_flg_pyh0_3;
	__u32 backpres_tx_pfc_flg_pyh4_7;
	__u16 backpres_tx_pfc_cnt;
	__u16 rx_pkt_ecn_cnt;
	__u8 backpres_rx_pfc_cnt;
	__u8 backpres_rx;
};

enum zxdh_health_check_reg_type {
	ZXDH_NORMAL_REG,
	ZXDH_WRITE_FIRST_REG,
	ZXDH_SMMU_REG,
};

struct zxdh_health_check_req {
	__u64 reg_va;
	__u64 value_va;
	__u64 reg_value_va_ex;
	__u16 count;
	__u8 reg_type : 2;
};

struct zxdh_health_check_resp {
	__u16 count;
	__u16 count_ex;
};

struct zxdh_reg_value {
	__u64 reg_addr;
	__u32 value;
};

enum zxdh_cfg_dev_parameter_type {
	TX_STOP_ON_AEQ = 1,
	RX_STOP_ON_AEQ,
	TXRX_STOP_IOVA_CAP,
	CLEAR_ALL_CC_BASIC_CNT,
};

struct zxdh_cfg_dev_parameter_req {
	__u8 type;
	__u8 reserved1;
	__u16 reserved2;
};

struct zxdh_db_show_res_map_req {
	__u8 type;
	__u32 qp_id;
	__u64 reg_va;
	__u64 value_va;
	__u64 idx_va;
	__u32 count;
};

struct zxdh_db_show_res_map_resp {
	__u32 count;
	__u64 qp_8k_index;
};

enum zxdh_show_res_map_type {
	ZXDH_SHOW_RES_MAP_PF_TO_QPN,
	ZXDH_SHOW_RES_MAP_PF_TO_VHCA,
	ZXDH_SHOW_RES_MAP_VHCA_TO_PF,
	ZXDH_SHOW_RES_MAP_8K_TO_GQP,
	ZXDH_SHOW_RES_MAP_GQP_TO_VHCA_CREATED,
	ZXDH_SHOW_RES_MAP_GQP_TO_VHCA_ACTIVE,
	ZXDH_SHOW_RES_MAP_QP_TO_8K,
	ZXDH_SHOW_RES_MAP_UNKNOWN,
};

int zxdh_get_log_trace_switch(struct ibv_context *context,
			      enum switch_status *status);
int zxdh_set_log_trace_switch(struct ibv_context *context,
			      enum switch_status status);
int zxdh_modify_qp_udp_sport(struct ibv_context *context, uint16_t udp_sport,
			     uint32_t qpn);
int zxdh_cap_start(struct ibv_context *context, struct zxdh_cap_cfg *cap_cfg,
		   struct zxdh_rdma_cap_pa *cap_pa);
int zxdh_cap_stop(struct ibv_context *context, uint8_t param);
int zxdh_cap_free(struct ibv_context *context, uint8_t param);
int zxdh_mp_capture(struct ibv_context *context,
		    struct zxdh_mp_cap_cfg *cap_mp_cfg,
		    struct zxdh_mp_cap_gqp *cap_mp_gqp);
int zxdh_mp_get_data(struct ibv_context *context, uint8_t param);
int zxdh_mp_capture_clear(struct ibv_context *context,
			  struct zxdh_cap_gqp *cap_gqp);
int zxdh_get_active_vhca_gqps(struct ibv_context *context,
			      struct zxdh_active_vhca_gqps *resp);
int zxdh_get_cc_basic_info(struct ibv_context *context,
			   struct zxdh_cc_basic_info *resp);
int zxdh_query_qpc(struct ibv_qp *qp, struct zxdh_rdma_qpc *qpc);
int zxdh_modify_qpc(struct ibv_qp *qp, struct zxdh_rdma_qpc *qpc,
		    uint64_t qpc_mask);
int zxdh_reset_qp(struct ibv_qp *qp, uint64_t opcode);
int zxdh_rdma_hmc_query(struct ibv_context *context,
			struct zxdh_context_req *req,
			struct zxdh_context_resp *resp);
int zxdh_get_object_data(struct ibv_context *context,
			 struct zxdh_get_object_data_req *req,
			 struct zxdh_get_object_data_resp *resp);
int zxdh_rdma_health_check(struct ibv_context *context,
			   struct zxdh_health_check_req *req,
			   struct zxdh_health_check_resp *resp);
int zxdh_cfg_dev_parameter(struct ibv_context *context,
			   struct zxdh_cfg_dev_parameter_req *req);
int zxdh_show_res_map(struct ibv_context *context,
		      struct zxdh_db_show_res_map_req *req,
		      struct zxdh_db_show_res_map_resp *resp);
#ifdef __cplusplus
}
#endif

#endif
