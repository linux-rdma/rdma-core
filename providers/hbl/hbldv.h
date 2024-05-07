/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright 2022-2024 HabanaLabs, Ltd.
 * Copyright (C) 2023-2024, Intel Corporation.
 * All Rights Reserved.
 */

#ifndef __HBLDV_H__
#define __HBLDV_H__

#include <stdbool.h>
#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Number of backpressure offsets */
#define HBLDV_USER_BP_OFFS_MAX			16

#define HBLDV_PORT_EX_ATTR_RESERVED0_NUM	2

#define HBL_IB_MTU_8192				6

/**
 * struct hbldv_qp_caps - HBL QP capabilities flags.
 * @HBLDV_QP_CAP_LOOPBACK: Enable QP loopback.
 * @HBLDV_QP_CAP_CONG_CTRL: Enable congestion control.
 * @HBLDV_QP_CAP_COMPRESSION: Enable compression.
 * @HBLDV_QP_CAP_ENCAP: Enable packet encapsulation.
 */
enum hbldv_qp_caps {
	HBLDV_QP_CAP_LOOPBACK = 0x1,
	HBLDV_QP_CAP_CONG_CTRL = 0x2,
	HBLDV_QP_CAP_COMPRESSION = 0x4,
	HBLDV_QP_CAP_RESERVED0 = 0x8,
	HBLDV_QP_CAP_ENCAP = 0x10,
	HBLDV_QP_CAP_RESERVED1 = 0x20,
};

/**
 * struct hbldv_port_ex_caps - HBL port extended capabilities flags.
 * @HBLDV_PORT_CAP_ADVANCED: Enable port advanced features like RDV, QMan, WTD, etc.
 * @HBLDV_PORT_CAP_ADAPTIVE_TIMEOUT: Enable adaptive timeout feature on this port.
 */
enum hbldv_port_ex_caps {
	HBLDV_PORT_CAP_ADVANCED = 0x1,
	HBLDV_PORT_CAP_ADAPTIVE_TIMEOUT = 0x2,
};

/**
 * enum hbldv_mem_id - Memory allocation methods.
 * @HBLDV_MEM_HOST: Memory allocated on the host.
 * @HBLDV_MEM_DEVICE: Memory allocated on the device.
 */
enum hbldv_mem_id {
	HBLDV_MEM_HOST = 1,
	HBLDV_MEM_DEVICE
};

/**
 * enum hbldv_wq_array_type - WQ-array type.
 * @HBLDV_WQ_ARRAY_TYPE_GENERIC: WQ-array for generic QPs.
 * @HBLDV_WQ_ARRAY_TYPE_MAX: Max number of values in this enum.
 */
enum hbldv_wq_array_type {
	HBLDV_WQ_ARRAY_TYPE_GENERIC,
	HBLDV_WQ_ARRAY_TYPE_RESERVED1,
	HBLDV_WQ_ARRAY_TYPE_RESERVED2,
	HBLDV_WQ_ARRAY_TYPE_RESERVED3,
	HBLDV_WQ_ARRAY_TYPE_RESERVED4,
	HBLDV_WQ_ARRAY_TYPE_MAX = 5,
};

/**
 * enum hbldv_swq_granularity - send WQE granularity.
 * @HBLDV_SWQE_GRAN_32B: 32 byte WQE for linear write.
 * @HBLDV_SWQE_GRAN_64B: 64 byte WQE for multi-stride write.
 */
enum hbldv_swq_granularity {
	HBLDV_SWQE_GRAN_32B,
	HBLDV_SWQE_GRAN_64B
};

/**
 * enum hbldv_usr_fifo_type - NIC users FIFO modes of operation.
 * @HBLDV_USR_FIFO_TYPE_DB: Mode for direct user door-bell submit.
 * @HBLDV_USR_FIFO_TYPE_CC: Mode for congestion control.
 */
enum hbldv_usr_fifo_type {
	HBLDV_USR_FIFO_TYPE_DB = 0,
	HBLDV_USR_FIFO_TYPE_CC,
};

/**
 * enum hbldv_qp_wq_types - QP WQ types.
 * @HBLDV_WQ_WRITE: WRITE or "native" SEND operations are allowed on this QP.
 *                  NOTE: the latter is currently unsupported.
 * @HBLDV_WQ_RECV_RDV: RECEIVE-RDV or WRITE operations are allowed on this QP.
 *                     NOTE: posting all operations at the same time is unsupported.
 * @HBLDV_WQ_READ_RDV: READ-RDV or WRITE operations are allowed on this QP.
 *                     NOTE: posting all operations at the same time is unsupported.
 * @HBLDV_WQ_SEND_RDV: SEND-RDV operation is allowed on this QP.
 * @HBLDV_WQ_READ_RDV_ENDP: No operation is allowed on this endpoint QP.
 */
enum hbldv_qp_wq_types {
	HBLDV_WQ_WRITE = 0x1,
	HBLDV_WQ_RECV_RDV = 0x2,
	HBLDV_WQ_READ_RDV = 0x4,
	HBLDV_WQ_SEND_RDV = 0x8,
	HBLDV_WQ_READ_RDV_ENDP = 0x10,
};

/**
 * enum hbldv_cq_type - CQ types, used during allocation of CQs.
 * @HBLDV_CQ_TYPE_QP: Standard CQ used for completion of a operation for a QP.
 * @HBLDV_CQ_TYPE_CC: Congestion control CQ.
 */
enum hbldv_cq_type {
	HBLDV_CQ_TYPE_QP = 0,
	HBLDV_CQ_TYPE_CC,
};

/**
 * enum hbldv_encap_type - Supported encapsulation types.
 * @HBLDV_ENCAP_TYPE_NO_ENC: No Tunneling.
 * @HBLDV_ENCAP_TYPE_ENC_OVER_IPV4: Tunnel RDMA packets through L3 layer.
 * @HBLDV_ENCAP_TYPE_ENC_OVER_UDP: Tunnel RDMA packets through L4 layer.
 */
enum hbldv_encap_type {
	HBLDV_ENCAP_TYPE_NO_ENC = 0,
	HBLDV_ENCAP_TYPE_ENC_OVER_IPV4,
	HBLDV_ENCAP_TYPE_ENC_OVER_UDP,
};

/**
 * enum hbldv_device_attr_caps - Device specific attributes.
 * @HBLDV_DEVICE_ATTR_CAP_CC: Congestion control.
 */
enum hbldv_device_attr_caps {
	HBLDV_DEVICE_ATTR_CAP_CC = 1 << 0,
};

/**
 * struct hbldv_ucontext_attr - HBL user context attributes.
 * @ports_mask: Mask of the relevant ports for this context (should be 1-based).
 * @core_fd: Core device file descriptor.
 */
struct hbldv_ucontext_attr {
	uint64_t ports_mask;
	int core_fd;
};

/**
 * struct hbldv_wq_array_attr - WQ-array attributes.
 * @max_num_of_wqs: Max number of WQs (QPs) to be used.
 * @max_num_of_wqes_in_wq: Max number of WQ elements in each WQ.
 * @mem_id: Memory allocation method.
 * @swq_granularity: Send WQE size.
 */
struct hbldv_wq_array_attr {
	uint32_t max_num_of_wqs;
	uint32_t max_num_of_wqes_in_wq;
	enum hbldv_mem_id mem_id;
	enum hbldv_swq_granularity swq_granularity;
};

/**
 * struct hbldv_port_ex_attr - HBL port extended attributes.
 * @wq_arr_attr: Array of WQ-array attributes for each WQ-array type.
 * @caps: Port capabilities bit-mask from hbldv_port_ex_caps.
 * @qp_wq_bp_offs: Offsets in NIC memory to signal a back pressure.
 * @port_num: Port ID (should be 1-based).
 */
struct hbldv_port_ex_attr {
	struct hbldv_wq_array_attr wq_arr_attr[HBLDV_WQ_ARRAY_TYPE_MAX];
	uint64_t caps;
	uint32_t qp_wq_bp_offs[HBLDV_USER_BP_OFFS_MAX];
	uint32_t reserved0[HBLDV_PORT_EX_ATTR_RESERVED0_NUM];
	uint32_t port_num;
	uint8_t reserved1;
};

/**
 * struct hbldv_query_port_attr - HBL query port specific parameters.
 * @max_num_of_qps: Number of QPs that are supported by the driver. User must allocate enough room
 *		    for his work-queues according to this number.
 * @num_allocated_qps: Number of QPs that were already allocated (in use).
 * @max_allocated_qp_num: The highest index of the allocated QPs (i.e. this is where the driver may
 *                        allocate its next QP).
 * @max_cq_size: Maximum size of a CQ buffer.
 * @advanced: true if advanced features are supported.
 * @max_num_of_cqs: Maximum number of CQs.
 * @max_num_of_usr_fifos: Maximum number of user FIFOs.
 * @max_num_of_encaps: Maximum number of encapsulations.
 * @nic_macro_idx: macro index of this specific port.
 * @nic_phys_port_idx: physical port index (AKA lane) of this specific port.
 */
struct hbldv_query_port_attr {
	uint32_t max_num_of_qps;
	uint32_t num_allocated_qps;
	uint32_t max_allocated_qp_num;
	uint32_t max_cq_size;
	uint32_t reserved0;
	uint32_t reserved1;
	uint32_t reserved2;
	uint32_t reserved3;
	uint32_t reserved4;
	uint8_t advanced;
	uint8_t max_num_of_cqs;
	uint8_t max_num_of_usr_fifos;
	uint8_t max_num_of_encaps;
	uint8_t nic_macro_idx;
	uint8_t nic_phys_port_idx;
};

/**
 * struct hbldv_qp_attr - HBL QP attributes.
 * @caps: QP capabilities bit-mask from hbldv_qp_caps.
 * @local_key: Unique key for local memory access. Needed for RTR state.
 * @remote_key: Unique key for remote memory access. Needed for RTS state.
 * @congestion_wnd: Congestion-Window size. Needed for RTS state.
 * @dest_wq_size: Number of WQEs on the destination. Needed for RDV RTS state.
 * @wq_type: WQ type. e.g. write, rdv etc. Needed for INIT state.
 * @wq_granularity: WQ granularity [0 for 32B or 1 for 64B]. Needed for INIT state.
 * @priority: QoS priority. Needed for RTR and RTS state.
 * @encap_num: Encapsulation ID. Needed for RTS and RTS state.
 */
struct hbldv_qp_attr {
	uint64_t caps;
	uint32_t local_key;
	uint32_t remote_key;
	uint32_t congestion_wnd;
	uint32_t reserved0;
	uint32_t dest_wq_size;
	enum hbldv_qp_wq_types wq_type;
	enum hbldv_swq_granularity wq_granularity;
	uint8_t priority;
	uint8_t reserved1;
	uint8_t reserved2;
	uint8_t encap_num;
	uint8_t reserved3;
};

/**
 * struct hbldv_query_qp_attr - Queried HBL QP data.
 * @qp_num: HBL QP num.
 * @swq_cpu_addr: Send WQ mmap address.
 * @rwq_cpu_addr: Receive WQ mmap address.
 */
struct hbldv_query_qp_attr {
	uint32_t qp_num;
	void *swq_cpu_addr;
	void *rwq_cpu_addr;
};

/**
 * struct hbldv_usr_fifo_attr - HBL user FIFO attributes.
 * @port_num: Port ID (should be 1-based).
 * @usr_fifo_num_hint: Hint to allocate a specific usr_fifo HW resource.
 * @usr_fifo_type: FIFO Operation type.
 */
struct hbldv_usr_fifo_attr {
	uint32_t port_num;
	uint32_t reserved0;
	uint32_t reserved1;
	uint32_t usr_fifo_num_hint;
	enum hbldv_usr_fifo_type usr_fifo_type;
	uint8_t reserved2;
};

/**
 * struct hbldv_usr_fifo - HBL user FIFO.
 * @ci_cpu_addr: CI mmap address.
 * @regs_cpu_addr: UMR mmap address.
 * @regs_offset: UMR offset.
 * @usr_fifo_num: DB FIFO ID.
 * @size: Allocated FIFO size.
 * @bp_thresh: Backpressure threshold that was set by the driver.
 */
struct hbldv_usr_fifo {
	void *ci_cpu_addr;
	void *regs_cpu_addr;
	uint32_t regs_offset;
	uint32_t usr_fifo_num;
	uint32_t size;
	uint32_t bp_thresh;
};

/**
 * struct hbldv_cq_attr - HBL CQ attributes.
 * @port_num: Port number to which CQ is associated (should be 1-based).
 * @cq_type: Type of CQ to be allocated.
 */
struct hbldv_cq_attr {
	uint8_t port_num;
	enum hbldv_cq_type cq_type;
};

/**
 * struct hbldv_cq - HBL CQ.
 * @ibvcq: Verbs CQ.
 * @mem_cpu_addr: CQ buffer address.
 * @pi_cpu_addr: CQ PI memory address.
 * @regs_cpu_addr: CQ UMR address.
 * @cq_size: Size of the CQ.
 * @cq_num: CQ number that is allocated.
 * @regs_offset: CQ UMR reg offset.
 */
struct hbldv_cq {
	struct ibv_cq *ibvcq;
	void *mem_cpu_addr;
	void *pi_cpu_addr;
	void *regs_cpu_addr;
	uint32_t cq_size;
	uint32_t cq_num;
	uint32_t regs_offset;
};

/**
 * struct hbldv_query_cq_attr - HBL CQ.
 * @ibvcq: Verbs CQ.
 * @mem_cpu_addr: CQ buffer address.
 * @pi_cpu_addr: CQ PI memory address.
 * @regs_cpu_addr: CQ UMR address.
 * @cq_size: Size of the CQ.
 * @cq_num: CQ number that is allocated.
 * @regs_offset: CQ UMR reg offset.
 * @cq_type: Type of CQ resource.
 */
struct hbldv_query_cq_attr {
	struct ibv_cq *ibvcq;
	void *mem_cpu_addr;
	void *pi_cpu_addr;
	void *regs_cpu_addr;
	uint32_t cq_size;
	uint32_t cq_num;
	uint32_t regs_offset;
	enum hbldv_cq_type cq_type;
};

/**
 * struct hbldv_encap_attr - HBL encapsulation specific attributes.
 * @tnl_hdr_ptr: Pointer to the tunnel encapsulation header. i.e. specific tunnel header data to be
 *               used in the encapsulation by the HW.
 * @tnl_hdr_size: Tunnel encapsulation header size.
 * @ipv4_addr: Source IP address, set regardless of encapsulation type.
 * @port_num: Port ID (should be 1-based).
 * @udp_dst_port: The UDP destination-port. Valid for L4 tunnel.
 * @ip_proto: IP protocol to use. Valid for L3 tunnel.
 * @encap_type: Encapsulation type. May be either no-encapsulation or encapsulation over L3 or L4.
 */
struct hbldv_encap_attr {
	uint64_t tnl_hdr_ptr;
	uint32_t tnl_hdr_size;
	uint32_t ipv4_addr;
	uint32_t port_num;
	union {
		uint16_t udp_dst_port;
		uint16_t ip_proto;
	};
	enum hbldv_encap_type encap_type;
};

/**
 * struct hbldv_encap - HBL DV encapsulation data.
 * @encap_num: HW encapsulation number.
 */
struct hbldv_encap {
	uint32_t encap_num;
};

/**
 * struct hbldv_cc_cq_attr - HBL congestion control CQ attributes.
 * @port_num: Port ID (should be 1-based).
 * @num_of_cqes: Number of CQ elements in CQ.
 */
struct hbldv_cc_cq_attr {
	uint32_t port_num;
	uint32_t num_of_cqes;
};

/**
 * struct hbldv_cc_cq - HBL congestion control CQ.
 * @mem_cpu_addr: CC CQ memory mmap address.
 * @pi_cpu_addr: CC CQ PI mmap address.
 * @cqe_size: CC CQ entry size.
 * @num_of_cqes: Number of CQ elements in CQ.
 */
struct hbldv_cc_cq {
	void *mem_cpu_addr;
	void *pi_cpu_addr;
	size_t cqe_size;
	uint32_t num_of_cqes;
};

/**
 * struct hbldv_device_attr - Devie specific attributes.
 * @caps: Capabilities mask.
 * @ports_mask: Mask of the relevant ports for this context (should be 1-based).
 */
struct hbldv_device_attr {
	uint64_t caps;
	uint64_t ports_mask;
};

bool hbldv_is_supported(struct ibv_device *device);
struct ibv_context *hbldv_open_device(struct ibv_device *device,
				      struct hbldv_ucontext_attr *attr);
int hbldv_set_port_ex(struct ibv_context *context, struct hbldv_port_ex_attr *attr);
/* port_num should be 1-based */
int hbldv_query_port(struct ibv_context *context, uint32_t port_num,
		     struct hbldv_query_port_attr *hbl_attr);
int hbldv_modify_qp(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask,
		    struct hbldv_qp_attr *hbl_attr);
struct hbldv_usr_fifo *hbldv_create_usr_fifo(struct ibv_context *context,
					     struct hbldv_usr_fifo_attr *attr);
int hbldv_destroy_usr_fifo(struct hbldv_usr_fifo *usr_fifo);
struct ibv_cq *hbldv_create_cq(struct ibv_context *context, int cqe,
			       struct ibv_comp_channel *channel, int comp_vector,
			       struct hbldv_cq_attr *cq_attr);
int hbldv_query_cq(struct ibv_cq *ibvcq, struct hbldv_query_cq_attr *hbl_cq);
int hbldv_query_qp(struct ibv_qp *ibvqp, struct hbldv_query_qp_attr *qp_attr);
struct hbldv_encap *hbldv_create_encap(struct ibv_context *context,
				       struct hbldv_encap_attr *encap_attr);
int hbldv_destroy_encap(struct hbldv_encap *hbl_encap);
int hbldv_query_device(struct ibv_context *context, struct hbldv_device_attr *attr);

#ifdef __cplusplus
}
#endif

#endif /* __HBLDV_H__ */
