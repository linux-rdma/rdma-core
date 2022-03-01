/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2016 - 2018 Intel Corporation.
 */

#ifndef IB_HDRS_H
#define IB_HDRS_H

#define __packed                        __attribute__((__packed__))
#define IB_QPN_MASK BTH_QPN_MASK
#define BIT(nr)                    ((unsigned long)(1) << (nr))
#include <linux/types.h>
#include <infiniband/verbs.h>

#define IB_SEQ_NAK	(3 << 29)

/* AETH NAK opcode values */
#define IB_RNR_NAK                      0x20
#define IB_NAK_PSN_ERROR                0x60
#define IB_NAK_INVALID_REQUEST          0x61
#define IB_NAK_REMOTE_ACCESS_ERROR      0x62
#define IB_NAK_REMOTE_OPERATIONAL_ERROR 0x63
#define IB_NAK_INVALID_RD_REQUEST       0x64

#define IB_BTH_REQ_ACK		BIT(31)
#define IB_BTH_SOLICITED	BIT(23)
#define IB_BTH_MIG_REQ		BIT(22)

#define IB_GRH_VERSION		6
#define IB_GRH_VERSION_MASK	0xF

#define IB_GRH_VERSION_SHIFT	28
#define IB_GRH_TCLASS_MASK	0xFF
#define IB_GRH_TCLASS_SHIFT	20
#define IB_GRH_FLOW_MASK	0xFFFFF
#define IB_GRH_FLOW_SHIFT	0
#define IB_GRH_NEXT_HDR		0x1B
#define IB_FECN_SHIFT 31
#define IB_FECN_MASK 1
#define IB_FECN_SMASK BIT(IB_FECN_SHIFT)
#define IB_BECN_SHIFT 30
#define IB_BECN_MASK 1
#define IB_BECN_SMASK BIT(IB_BECN_SHIFT)

#define IB_AETH_CREDIT_SHIFT	24
#define IB_AETH_CREDIT_MASK	0x1F
#define IB_AETH_CREDIT_INVAL	0x1F
#define IB_AETH_NAK_SHIFT	29
#define IB_MSN_MASK		0xFFFFFF

struct ib_reth {
	__be64 vaddr;        /* potentially unaligned */
	__be32 rkey;
	__be32 length;
} __packed;

struct ib_atomic_eth {
	__be64 vaddr;        /* potentially unaligned */
	__be32 rkey;
	__be64 swap_data;    /* potentially unaligned */
	__be64 compare_data; /* potentially unaligned */
} __packed;

#include "tid_rdma_defs.h"

union ib_ehdrs {
	struct {
		__be32 deth[2];
		__be32 imm_data;
	} ud;
	struct {
		struct ib_reth reth;
		__be32 imm_data;
	} rc;
	struct {
		__be32 aeth;
		__be64 atomic_ack_eth; /* potentially unaligned */
	} __packed at;
	__be32 imm_data;
	__be32 aeth;
	__be32 ieth;
	struct ib_atomic_eth atomic_eth;
	/* TID RDMA headers */
	union {
		struct tid_rdma_read_req r_req;
		struct tid_rdma_read_resp r_rsp;
		struct tid_rdma_write_req w_req;
		struct tid_rdma_write_resp w_rsp;
		struct tid_rdma_write_data w_data;
		struct tid_rdma_resync resync;
		struct tid_rdma_ack ack;
	} tid_rdma;
}  __packed;

struct ib_other_headers {
	__be32 bth[3];
	union ib_ehdrs u;
} __packed;

struct ib_header {
	__be16 lrh[4];
	union {
		struct {
			struct ibv_grh grh;
			struct ib_other_headers oth;
		} l;
		struct ib_other_headers oth;
	} u;
} __packed;

/*
 * 9B/IB Packet Format
 */
#define IB_LNH_MASK		3
#define IB_SC_MASK		0xf
#define IB_SC_SHIFT		12
#define IB_SC5_MASK		0x10
#define IB_SL_MASK		0xf
#define IB_SL_SHIFT		4
#define IB_SL_SHIFT		4
#define IB_LVER_MASK	0xf
#define IB_LVER_SHIFT	8

static inline uint8_t ib_get_lnh(struct ib_header *hdr)
{
	return (ntohs(hdr->lrh[0]) & IB_LNH_MASK);
}

static inline uint8_t ib_get_sc(struct ib_header *hdr)
{
	return ((ntohs(hdr->lrh[0]) >> IB_SC_SHIFT) & IB_SC_MASK);
}

static inline bool ib_is_sc5(uint16_t sc5)
{
	return !!(sc5 & IB_SC5_MASK);
}

static inline uint8_t ib_get_sl(struct ib_header *hdr)
{
	return ((ntohs(hdr->lrh[0]) >> IB_SL_SHIFT) & IB_SL_MASK);
}

static inline uint16_t ib_get_dlid(struct ib_header *hdr)
{
	return (ntohs(hdr->lrh[1]));
}

static inline uint16_t ib_get_slid(struct ib_header *hdr)
{
	return (ntohs(hdr->lrh[3]));
}

static inline uint8_t ib_get_lver(struct ib_header *hdr)
{
	return (uint8_t)((ntohs(hdr->lrh[0]) >> IB_LVER_SHIFT) &
		   IB_LVER_MASK);
}

static inline uint32_t ib_get_qkey(struct ib_other_headers *ohdr)
{
	return ntohl(ohdr->u.ud.deth[0]);
}

static inline uint32_t ib_get_sqpn(struct ib_other_headers *ohdr)
{
	return ((ntohl(ohdr->u.ud.deth[1])) & IB_QPN_MASK);
}

/*
 * BTH
 */
#define IB_BTH_OPCODE_MASK	0xff
#define IB_BTH_OPCODE_SHIFT	24
#define IB_BTH_PAD_MASK	3
#define IB_BTH_PKEY_MASK	0xffff
#define IB_BTH_PAD_SHIFT	20
#define IB_BTH_A_MASK		1
#define IB_BTH_A_SHIFT		31
#define IB_BTH_M_MASK		1
#define IB_BTH_M_SHIFT		22
#define IB_BTH_SE_MASK		1
#define IB_BTH_SE_SHIFT	23
#define IB_BTH_TVER_MASK	0xf
#define IB_BTH_TVER_SHIFT	16
#define IB_BTH_OPCODE_CNP	0x81

static inline uint8_t ib_bth_get_pad(struct ib_other_headers *ohdr)
{
	return ((ntohl(ohdr->bth[0]) >> IB_BTH_PAD_SHIFT) &
		   IB_BTH_PAD_MASK);
}

static inline uint16_t ib_bth_get_pkey(struct ib_other_headers *ohdr)
{
	return (ntohl(ohdr->bth[0]) & IB_BTH_PKEY_MASK);
}

static inline uint8_t ib_bth_get_opcode(struct ib_other_headers *ohdr)
{
	return ((ntohl(ohdr->bth[0]) >> IB_BTH_OPCODE_SHIFT) &
		   IB_BTH_OPCODE_MASK);
}

static inline uint8_t ib_bth_get_ackreq(struct ib_other_headers *ohdr)
{
	return (uint8_t)((ntohl(ohdr->bth[2]) >> IB_BTH_A_SHIFT) &
		   IB_BTH_A_MASK);
}

static inline uint8_t ib_bth_get_migreq(struct ib_other_headers *ohdr)
{
	return (uint8_t)((ntohl(ohdr->bth[0]) >> IB_BTH_M_SHIFT) &
		    IB_BTH_M_MASK);
}

static inline uint8_t ib_bth_get_se(struct ib_other_headers *ohdr)
{
	return (uint8_t)((ntohl(ohdr->bth[0]) >> IB_BTH_SE_SHIFT) &
		    IB_BTH_SE_MASK);
}

static inline uint32_t ib_bth_get_psn(struct ib_other_headers *ohdr)
{
	return (uint32_t)(ntohl(ohdr->bth[2]));
}

static inline uint32_t ib_bth_get_qpn(struct ib_other_headers *ohdr)
{
	return (uint32_t)((ntohl(ohdr->bth[1])) & IB_QPN_MASK);
}

static inline bool ib_bth_get_becn(struct ib_other_headers *ohdr)
{
	return (ohdr->bth[1]) & htonl(IB_BECN_SMASK);
}

static inline bool ib_bth_get_fecn(struct ib_other_headers *ohdr)
{
	return (ohdr->bth[1]) & htonl(IB_FECN_SMASK);
}

static inline uint8_t ib_bth_get_tver(struct ib_other_headers *ohdr)
{
	return (uint8_t)((ntohl(ohdr->bth[0]) >> IB_BTH_TVER_SHIFT)  &
		    IB_BTH_TVER_MASK);
}

static inline bool ib_bth_is_solicited(struct ib_other_headers *ohdr)
{
	return ohdr->bth[0] & htonl(IB_BTH_SOLICITED);
}

static inline bool ib_bth_is_migration(struct ib_other_headers *ohdr)
{
	return ohdr->bth[0] & htonl(IB_BTH_MIG_REQ);
}
#endif                          /* IB_HDRS_H */
