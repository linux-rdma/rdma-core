/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 * Copyright (c) 2022 Christoph Lameter <cl@linux.com>. All rights reserved.
 *
 * Taken from the RXE driver code in the kernel and from the header
 * file linux/include/rdma/ib_pack.h
 */

#ifndef BTH_HDR_H
#define BTH_HDR_H

enum {
	IB_LRH_BYTES		= 8,
	IB_ETH_BYTES		= 14,
	IB_VLAN_BYTES		= 4,
	IB_GRH_BYTES		= 40,
	IB_IP4_BYTES		= 20,
	IB_UDP_BYTES		= 8,
	IB_BTH_BYTES		= 12,
	IB_DETH_BYTES		= 8,
	IB_EXT_ATOMICETH_BYTES	= 28,
	IB_EXT_XRC_BYTES	= 4,
	IB_ICRC_BYTES		= 4
};

/*
 * This macro cleans up the definitions of constants for BTH opcodes.
 * It is used to define constants such as IB_OPCODE_UD_SEND_ONLY,
 * which becomes IB_OPCODE_UD + IB_OPCODE_SEND_ONLY, and this gives
 * the correct value.
 *
 * In short, user code should use the constants defined using the
 * macro rather than worrying about adding together other constants.
*/
#define IB_OPCODE(transport, op) \
	IB_OPCODE_ ## transport ## _ ## op = \
		IB_OPCODE_ ## transport + IB_OPCODE_ ## op

enum {
	/* transport types -- just used to define real constants */
	IB_OPCODE_RC                                = 0x00,
	IB_OPCODE_UC                                = 0x20,
	IB_OPCODE_RD                                = 0x40,
	IB_OPCODE_UD                                = 0x60,
	/* per IBTA 1.3 vol 1 Table 38, A10.3.2 */
	IB_OPCODE_CNP                               = 0x80,
	/* Manufacturer specific */
	IB_OPCODE_MSP                               = 0xe0,

	/* operations -- just used to define real constants */
	IB_OPCODE_SEND_FIRST                        = 0x00,
	IB_OPCODE_SEND_MIDDLE                       = 0x01,
	IB_OPCODE_SEND_LAST                         = 0x02,
	IB_OPCODE_SEND_LAST_WITH_IMMEDIATE          = 0x03,
	IB_OPCODE_SEND_ONLY                         = 0x04,
	IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE          = 0x05,
	IB_OPCODE_RDMA_WRITE_FIRST                  = 0x06,
	IB_OPCODE_RDMA_WRITE_MIDDLE                 = 0x07,
	IB_OPCODE_RDMA_WRITE_LAST                   = 0x08,
	IB_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE    = 0x09,
	IB_OPCODE_RDMA_WRITE_ONLY                   = 0x0a,
	IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE    = 0x0b,
	IB_OPCODE_RDMA_READ_REQUEST                 = 0x0c,
	IB_OPCODE_RDMA_READ_RESPONSE_FIRST          = 0x0d,
	IB_OPCODE_RDMA_READ_RESPONSE_MIDDLE         = 0x0e,
	IB_OPCODE_RDMA_READ_RESPONSE_LAST           = 0x0f,
	IB_OPCODE_RDMA_READ_RESPONSE_ONLY           = 0x10,
	IB_OPCODE_ACKNOWLEDGE                       = 0x11,
	IB_OPCODE_ATOMIC_ACKNOWLEDGE                = 0x12,
	IB_OPCODE_COMPARE_SWAP                      = 0x13,
	IB_OPCODE_FETCH_ADD                         = 0x14,
	/* opcode 0x15 is reserved */
	IB_OPCODE_SEND_LAST_WITH_INVALIDATE         = 0x16,
	IB_OPCODE_SEND_ONLY_WITH_INVALIDATE         = 0x17,

	/* real constants follow -- see comment about above IB_OPCODE()
	   macro for more details */

	/* RC */
	IB_OPCODE(RC, SEND_FIRST),
	IB_OPCODE(RC, SEND_MIDDLE),
	IB_OPCODE(RC, SEND_LAST),
	IB_OPCODE(RC, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RC, SEND_ONLY),
	IB_OPCODE(RC, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_WRITE_FIRST),
	IB_OPCODE(RC, RDMA_WRITE_MIDDLE),
	IB_OPCODE(RC, RDMA_WRITE_LAST),
	IB_OPCODE(RC, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_WRITE_ONLY),
	IB_OPCODE(RC, RDMA_WRITE_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_READ_REQUEST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_FIRST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_MIDDLE),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_LAST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_ONLY),
	IB_OPCODE(RC, ACKNOWLEDGE),
	IB_OPCODE(RC, ATOMIC_ACKNOWLEDGE),
	IB_OPCODE(RC, COMPARE_SWAP),
	IB_OPCODE(RC, FETCH_ADD),
	IB_OPCODE(RC, SEND_LAST_WITH_INVALIDATE),
	IB_OPCODE(RC, SEND_ONLY_WITH_INVALIDATE),

	/* UC */
	IB_OPCODE(UC, SEND_FIRST),
	IB_OPCODE(UC, SEND_MIDDLE),
	IB_OPCODE(UC, SEND_LAST),
	IB_OPCODE(UC, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(UC, SEND_ONLY),
	IB_OPCODE(UC, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(UC, RDMA_WRITE_FIRST),
	IB_OPCODE(UC, RDMA_WRITE_MIDDLE),
	IB_OPCODE(UC, RDMA_WRITE_LAST),
	IB_OPCODE(UC, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(UC, RDMA_WRITE_ONLY),
	IB_OPCODE(UC, RDMA_WRITE_ONLY_WITH_IMMEDIATE),

	/* RD */
	IB_OPCODE(RD, SEND_FIRST),
	IB_OPCODE(RD, SEND_MIDDLE),
	IB_OPCODE(RD, SEND_LAST),
	IB_OPCODE(RD, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RD, SEND_ONLY),
	IB_OPCODE(RD, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_WRITE_FIRST),
	IB_OPCODE(RD, RDMA_WRITE_MIDDLE),
	IB_OPCODE(RD, RDMA_WRITE_LAST),
	IB_OPCODE(RD, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_WRITE_ONLY),
	IB_OPCODE(RD, RDMA_WRITE_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_READ_REQUEST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_FIRST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_MIDDLE),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_LAST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_ONLY),
	IB_OPCODE(RD, ACKNOWLEDGE),
	IB_OPCODE(RD, ATOMIC_ACKNOWLEDGE),
	IB_OPCODE(RD, COMPARE_SWAP),
	IB_OPCODE(RD, FETCH_ADD),

	/* UD */
	IB_OPCODE(UD, SEND_ONLY),
	IB_OPCODE(UD, SEND_ONLY_WITH_IMMEDIATE)
};


/*
 * IBA header types and methods
 *
 * Header specific routines to insert/extract values to/from headers
 * the routines that are named __hhh_(set_)fff() take a pointer to a
 * hhh header and get(set) the fff field. The routines named
 * hhh_(set_)fff take a packet info struct and find the
 * header and field based on the opcode in the packet.
 * Conversion to/from network byte order from cpu order is also done.
 */

#define ICRC_SIZE		(4)
#define BTHE_MAX_HDR_LENGTH	(80)

/******************************************************************************
 * Base Transport Header
 ******************************************************************************/
struct bth {
	uint8_t			opcode;
	uint8_t			flags;
	uint16_t		pkey;
	uint32_t		qpn;
	uint32_t		apsn;
};

#define BTH_TVER		(0)
#define BTH_DEF_PKEY		(0xffff)

#define BTH_SE_MASK		(0x80)
#define BTH_MIG_MASK		(0x40)
#define BTH_PAD_MASK		(0x30)
#define BTH_TVER_MASK		(0x0f)
#define BTH_FECN_MASK		(0x80000000)
#define BTH_BECN_MASK		(0x40000000)
#define BTH_RESV6A_MASK		(0x3f000000)
#define BTH_QPN_MASK		(0x00ffffff)
#define BTH_ACK_MASK		(0x80000000)
#define BTH_RESV7_MASK		(0x7f000000)
#define BTH_PSN_MASK		(0x00ffffff)

static inline uint8_t __bth_opcode(void *arg)
{
	struct bth *bth = arg;

	return bth->opcode;
}

static inline void __bth_set_opcode(void *arg, uint8_t opcode)
{
	struct bth *bth = arg;

	bth->opcode = opcode;
}

static inline uint8_t __bth_se(void *arg)
{
	struct bth *bth = arg;

	return 0 != (BTH_SE_MASK & bth->flags);
}

static inline void __bth_set_se(void *arg, int se)
{
	struct bth *bth = arg;

	if (se)
		bth->flags |= BTH_SE_MASK;
	else
		bth->flags &= ~BTH_SE_MASK;
}

static inline uint8_t __bth_mig(void *arg)
{
	struct bth *bth = arg;

	return 0 != (BTH_MIG_MASK & bth->flags);
}

static inline void __bth_set_mig(void *arg, uint8_t mig)
{
	struct bth *bth = arg;

	if (mig)
		bth->flags |= BTH_MIG_MASK;
	else
		bth->flags &= ~BTH_MIG_MASK;
}

static inline uint8_t __bth_pad(void *arg)
{
	struct bth *bth = arg;

	return (BTH_PAD_MASK & bth->flags) >> 4;
}

static inline void __bth_set_pad(void *arg, uint8_t pad)
{
	struct bth *bth = arg;

	bth->flags = (BTH_PAD_MASK & (pad << 4)) |
			(~BTH_PAD_MASK & bth->flags);
}

static inline uint8_t __bth_tver(void *arg)
{
	struct bth *bth = arg;

	return BTH_TVER_MASK & bth->flags;
}

static inline void __bth_set_tver(void *arg, uint8_t tver)
{
	struct bth *bth = arg;

	bth->flags = (BTH_TVER_MASK & tver) |
			(~BTH_TVER_MASK & bth->flags);
}

static inline uint16_t __bth_pkey(void *arg)
{
	struct bth *bth = arg;

	return ntohs(bth->pkey);
}

static inline void __bth_set_pkey(void *arg, uint16_t pkey)
{
	struct bth *bth = arg;

	bth->pkey = ntohs(pkey);
}

static inline uint32_t __bth_qpn(void *arg)
{
	struct bth *bth = arg;

	return BTH_QPN_MASK & ntohl(bth->qpn);
}

static inline void __bth_set_qpn(void *arg, uint32_t qpn)
{
	struct bth *bth = arg;
	uint32_t resvqpn = ntohl(bth->qpn);

	bth->qpn = ntohl((BTH_QPN_MASK & qpn) |
			       (~BTH_QPN_MASK & resvqpn));
}

static inline int __bth_fecn(void *arg)
{
	struct bth *bth = arg;

	return 0 != (ntohl(BTH_FECN_MASK) & bth->qpn);
}

static inline void __bth_set_fecn(void *arg, int fecn)
{
	struct bth *bth = arg;

	if (fecn)
		bth->qpn |= ntohl(BTH_FECN_MASK);
	else
		bth->qpn &= ~ntohl(BTH_FECN_MASK);
}

static inline int __bth_becn(void *arg)
{
	struct bth *bth = arg;

	return 0 != (ntohl(BTH_BECN_MASK) & bth->qpn);
}

static inline void __bth_set_becn(void *arg, int becn)
{
	struct bth *bth = arg;

	if (becn)
		bth->qpn |= ntohl(BTH_BECN_MASK);
	else
		bth->qpn &= ~ntohl(BTH_BECN_MASK);
}

static inline uint8_t __bth_resv6a(void *arg)
{
	struct bth *bth = arg;

	return (BTH_RESV6A_MASK & ntohl(bth->qpn)) >> 24;
}

static inline void __bth_set_resv6a(void *arg)
{
	struct bth *bth = arg;

	bth->qpn = htonl(~BTH_RESV6A_MASK);
}

static inline int __bth_ack(void *arg)
{
	struct bth *bth = arg;

	return 0 != (htonl(BTH_ACK_MASK) & bth->apsn);
}

static inline void __bth_set_ack(void *arg, int ack)
{
	struct bth *bth = arg;

	if (ack)
		bth->apsn |= htonl(BTH_ACK_MASK);
	else
		bth->apsn &= ~htonl(BTH_ACK_MASK);
}

static inline void __bth_set_resv7(void *arg)
{
	struct bth *bth = arg;

	bth->apsn &= ~htonl(BTH_RESV7_MASK);
}

static inline uint32_t __bth_psn(void *arg)
{
	struct bth *bth = arg;

	return BTH_PSN_MASK & ntohl(bth->apsn);
}

static inline void __bth_set_psn(void *arg, uint32_t psn)
{
	struct bth *bth = arg;
	uint32_t apsn = ntohl(bth->apsn);

	bth->apsn = htonl((BTH_PSN_MASK & psn) |
			(~BTH_PSN_MASK & apsn));
}

/******************************************************************************
 * Reliable Datagram Extended Transport Header
 ******************************************************************************/
struct rdeth {
	uint32_t		een;
};

#define RDETH_EEN_MASK		(0x00ffffff)

static inline uint8_t __rdeth_een(void *arg)
{
	struct rdeth *rdeth = arg;

	return RDETH_EEN_MASK & ntohl(rdeth->een);
}

static inline void __rdeth_set_een(void *arg, uint32_t een)
{
	struct rdeth *rdeth = arg;

	rdeth->een = htonl(RDETH_EEN_MASK & een);
}

/******************************************************************************
 * Datagram Extended Transport Header
 ******************************************************************************/
struct deth {
	uint32_t		qkey;
	uint32_t		sqp;
};

#define GSI_QKEY		(0x80010000)
#define DETH_SQP_MASK		(0x00ffffff)

static inline uint32_t __deth_qkey(void *arg)
{
	struct deth *deth = arg;

	return ntohl(deth->qkey);
}

static inline void __deth_set_qkey(void *arg, uint32_t qkey)
{
	struct deth *deth = arg;

	deth->qkey = htonl(qkey);
}

static inline uint32_t __deth_sqp(void *arg)
{
	struct deth *deth = arg;

	return DETH_SQP_MASK & ntohl(deth->sqp);
}

static inline void __deth_set_sqp(void *arg, uint32_t sqp)
{
	struct deth *deth = arg;

	deth->sqp = htonl(DETH_SQP_MASK & sqp);
}

/******************************************************************************
 * RDMA Extended Transport Header
 ******************************************************************************/
struct reth {
	uint64_t	va;
	uint32_t	rkey;
	uint32_t	len;
};

static inline uint64_t __reth_va(void *arg)
{
	struct reth *reth = arg;

	return be64toh(reth->va);
}

static inline void __reth_set_va(void *arg, uint64_t va)
{
	struct reth *reth = arg;

	reth->va = htobe64(va);
}

static inline uint32_t __reth_rkey(void *arg)
{
	struct reth *reth = arg;

	return ntohl(reth->rkey);
}

static inline void __reth_set_rkey(void *arg, uint32_t rkey)
{
	struct reth *reth = arg;

	reth->rkey = htonl(rkey);
}

static inline uint32_t __reth_len(void *arg)
{
	struct reth *reth = arg;

	return ntohl(reth->len);
}

static inline void __reth_set_len(void *arg, uint32_t len)
{
	struct reth *reth = arg;

	reth->len = htonl(len);
}

/******************************************************************************
 * Atomic Extended Transport Header
 ******************************************************************************/
struct atmeth {
	uint64_t		va;
	uint32_t		rkey;
	uint64_t		swap_add;
	uint64_t		comp;
} __packed;

static inline uint64_t __atmeth_va(void *arg)
{
	struct atmeth *atmeth = arg;

	return be64toh(atmeth->va);
}

static inline void __atmeth_set_va(void *arg, uint64_t va)
{
	struct atmeth *atmeth = arg;

	atmeth->va = htobe64(va);
}

static inline uint32_t __atmeth_rkey(void *arg)
{
	struct atmeth *atmeth = arg;

	return htonl(atmeth->rkey);
}

static inline void __atmeth_set_rkey(void *arg, uint32_t rkey)
{
	struct atmeth *atmeth = arg;

	atmeth->rkey = htonl(rkey);
}

static inline uint64_t __atmeth_swap_add(void *arg)
{
	struct atmeth *atmeth = arg;

	return be64toh(atmeth->swap_add);
}

static inline void __atmeth_set_swap_add(void *arg, uint64_t swap_add)
{
	struct atmeth *atmeth = arg;

	atmeth->swap_add = htobe64(swap_add);
}

static inline uint64_t __atmeth_comp(void *arg)
{
	struct atmeth *atmeth = arg;

	return be64toh(atmeth->comp);
}

static inline void __atmeth_set_comp(void *arg, uint64_t comp)
{
	struct atmeth *atmeth = arg;

	atmeth->comp = htobe64(comp);
}

/******************************************************************************
 * Ack Extended Transport Header
 ******************************************************************************/
struct aeth {
	uint32_t	smsn;
};

#define AETH_SYN_MASK		(0xff000000)
#define AETH_MSN_MASK		(0x00ffffff)

enum aeth_syndrome {
	AETH_TYPE_MASK		= 0xe0,
	AETH_ACK		= 0x00,
	AETH_RNR_NAK		= 0x20,
	AETH_RSVD		= 0x40,
	AETH_NAK		= 0x60,
	AETH_ACK_UNLIMITED	= 0x1f,
	AETH_NAK_PSN_SEQ_ERROR	= 0x60,
	AETH_NAK_INVALID_REQ	= 0x61,
	AETH_NAK_REM_ACC_ERR	= 0x62,
	AETH_NAK_REM_OP_ERR	= 0x63,
	AETH_NAK_INV_RD_REQ	= 0x64,
};

static inline uint8_t __aeth_syn(void *arg)
{
	struct aeth *aeth = arg;

	return (AETH_SYN_MASK & ntohl(aeth->smsn)) >> 24;
}

static inline void __aeth_set_syn(void *arg, uint8_t syn)
{
	struct aeth *aeth = arg;
	uint32_t smsn = ntohl(aeth->smsn);

	aeth->smsn = htonl((AETH_SYN_MASK & (syn << 24)) |
			 (~AETH_SYN_MASK & smsn));
}

static inline uint32_t __aeth_msn(void *arg)
{
	struct aeth *aeth = arg;

	return AETH_MSN_MASK & ntohl(aeth->smsn);
}

static inline void __aeth_set_msn(void *arg, uint32_t msn)
{
	struct aeth *aeth = arg;
	uint32_t smsn = ntohl(aeth->smsn);

	aeth->smsn = htonl((AETH_MSN_MASK & msn) |
			 (~AETH_MSN_MASK & smsn));
}

/******************************************************************************
 * Atomic Ack Extended Transport Header
 ******************************************************************************/
struct atmack {
	uint64_t		orig;
};

static inline uint64_t __atmack_orig(void *arg)
{
	struct atmack *atmack = arg;

	return be64toh(atmack->orig);
}

static inline void __atmack_set_orig(void *arg, uint64_t orig)
{
	struct atmack *atmack = arg;

	atmack->orig = htobe64(orig);
}

/******************************************************************************
 * Immediate Extended Transport Header
 ******************************************************************************/
struct immdt {
	uint32_t	imm;
};

static inline uint32_t __immdt_imm(void *arg)
{
	struct immdt *immdt = arg;

	return immdt->imm;
}

static inline void __immdt_set_imm(void *arg, uint32_t imm)
{
	struct immdt *immdt = arg;

	immdt->imm = imm;
}

/******************************************************************************
 * Invalidate Extended Transport Header
 ******************************************************************************/
struct ieth {
	uint32_t	rkey;
};

static inline uint32_t __ieth_rkey(void *arg)
{
	struct ieth *ieth = arg;

	return ntohl(ieth->rkey);
}

static inline void __ieth_set_rkey(void *arg, uint32_t rkey)
{
	struct ieth *ieth = arg;

	ieth->rkey = ntohl(rkey);
}

enum hdr_length {
	BTH_BYTES		= sizeof(struct bth),
	IMMDT_BYTES		= sizeof(struct immdt),
	RETH_BYTES		= sizeof(struct reth),
	AETH_BYTES		= sizeof(struct aeth),
	ATMACK_BYTES	= sizeof(struct atmack),
	ATMETH_BYTES	= sizeof(struct atmeth),
	IETH_BYTES		= sizeof(struct ieth),
	RDETH_BYTES		= sizeof(struct rdeth),
};

#endif /* BTH_HDR_H */
