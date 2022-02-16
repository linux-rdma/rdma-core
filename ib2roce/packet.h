/* vim:ts=8:sts=4:sw=4:noai:noexpandtab
 * 
 * PGM packet formats, RFC 3208.
 *
 * Copyright (c) 2006-2011 Miru Limited.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* protocol number assigned by IANA */
#ifndef IPPROTO_PGM
#	define IPPROTO_PGM 		    	113
#endif

/* read from /etc/protocols if available */
extern int pgm_ipproto_pgm;


/* address family indicator, rfc 1700 (ADDRESS FAMILY NUMBERS) */
#ifndef AFI_IP
#	define AFI_IP	    1	    /* IP (IP version 4) */
#	define AFI_IP6	    2	    /* IP6 (IP version 6) */
#endif

/* UDP ports for UDP encapsulation, as per IBM WebSphere MQ */
#define DEFAULT_UDP_ENCAP_UCAST_PORT	3055
#define DEFAULT_UDP_ENCAP_MCAST_PORT	3056

/* PGM default ports */
#define DEFAULT_DATA_DESTINATION_PORT	7500
#define DEFAULT_DATA_SOURCE_PORT	0	/* random */

/* DoS limitation to protocol (MS08-036, KB950762) */
#ifndef PGM_MAX_APDU
#	define PGM_MAX_APDU			UINT16_MAX
#endif

/* Cisco default: 24 (max 8200), Juniper & H3C default: 16, SmartPGM: 64 */
#ifndef PGM_MAX_FRAGMENTS
#	define PGM_MAX_FRAGMENTS		16
#endif


enum pgm_type_e {
	PGM_SPM		= 0x00,	/* 8.1: source path message */
	PGM_POLL	= 0x01,	/* 14.7.1: poll request */
	PGM_POLR	= 0x02,	/* 14.7.2: poll response */
	PGM_ODATA	= 0x04,	/* 8.2: original data */
	PGM_RDATA	= 0x05,	/* 8.2: repair data */
	PGM_NAK		= 0x08,	/* 8.3: NAK or negative acknowledgement */
	PGM_NNAK	= 0x09,	/* 8.3: N-NAK or null negative acknowledgement */
	PGM_NCF		= 0x0a,	/* 8.3: NCF or NAK confirmation */
	PGM_SPMR	= 0x0c,	/* 13.6: SPM request */
	PGM_ACK		= 0x0d,	/* PGMCC: congestion control ACK */
	PGM_MAX		= 0xff
};

#define PGM_OPT_LENGTH		    0x00	/* options length */
#define PGM_OPT_FRAGMENT	    0x01	/* fragmentation */
#define PGM_OPT_NAK_LIST	    0x02	/* list of nak entries */
#define PGM_OPT_JOIN		    0x03	/* late joining */
#define PGM_OPT_REDIRECT	    0x07	/* redirect */
#define PGM_OPT_SYN		    0x0d	/* synchronisation */
#define PGM_OPT_FIN		    0x0e	/* session end */
#define PGM_OPT_RST		    0x0f	/* session reset */

#define PGM_OPT_PARITY_PRM	    0x08	/* forward error correction parameters */
#define PGM_OPT_PARITY_GRP	    0x09	/*   group number */
#define PGM_OPT_CURR_TGSIZE	    0x0a	/*   group size */

#define PGM_OPT_CR		    0x10	/* congestion report */
#define PGM_OPT_CRQST		    0x11	/* congestion report request */

#define PGM_OPT_PGMCC_DATA	    0x12
#define PGM_OPT_PGMCC_FEEDBACK	    0x13

#define PGM_OPT_NAK_BO_IVL	    0x04	/* nak back-off interval */
#define PGM_OPT_NAK_BO_RNG	    0x05	/* nak back-off range */
#define PGM_OPT_NBR_UNREACH	    0x0b	/* neighbour unreachable */
#define PGM_OPT_PATH_NLA	    0x0c	/* path nla */

#define PGM_OPT_INVALID		    0x7f	/* option invalidated */

/* byte alignment for packet memory maps 
 * pack broken on GCC pre-3.5: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=7054
 */
#if (defined( __GNUC__ ) && ( __GNUC__ >= 4 )) && !defined( __sun ) && !defined( __CYGWIN__ )
#	pragma pack(push)
#endif
#pragma pack(1)

/* 8. PGM header */
struct pgm_header {
	uint16_t	pgm_sport;		/* source port: tsi::sport or UDP port depending on direction */
	uint16_t	pgm_dport;		/* destination port */
	uint8_t		pgm_type;		/* version / packet type */
	uint8_t		pgm_options;		/* options */
#define PGM_OPT_PARITY		0x80	/* parity packet */
#define PGM_OPT_VAR_PKTLEN	0x40	/* + variable sized packets */
#define PGM_OPT_NETWORK		0x02    /* network-significant: must be interpreted by network elements */
#define PGM_OPT_PRESENT		0x01	/* option extension are present */
	uint16_t	pgm_checksum;		/* checksum */
	uint8_t		pgm_gsi[6];		/* global source id */
	uint16_t	pgm_tsdu_length;	/* tsdu length */
				/* tpdu length = th length (header + options) + tsdu length */
};

/* 8.1.  Source Path Messages (SPM) */
struct pgm_spm {
	uint32_t	spm_sqn;		/* spm sequence number */
	uint32_t	spm_trail;		/* trailing edge sequence number */
	uint32_t	spm_lead;		/* leading edge sequence number */
	uint16_t	spm_nla_afi;		/* nla afi */
	uint16_t	spm_reserved;		/* reserved */
	struct in_addr	spm_nla;		/* path nla */
	/* ... option extensions */
};

struct pgm_spm6 {
	uint32_t	spm6_sqn;		/* spm sequence number */
	uint32_t	spm6_trail;		/* trailing edge sequence number */
	uint32_t	spm6_lead;		/* leading edge sequence number */
	uint16_t	spm6_nla_afi;		/* nla afi */
	uint16_t	spm6_reserved;		/* reserved */
	struct in6_addr spm6_nla;		/* path nla */
	/* ... option extensions */
};

/* 8.2.  Data Packet */
struct pgm_data {
	uint32_t	data_sqn;		/* data packet sequence number */
	uint32_t	data_trail;		/* trailing edge sequence number */
	/* ... option extensions */
	/* ... data */
};

/* 8.3.  Negative Acknowledgments and Confirmations (NAK, N-NAK, & NCF) */
struct pgm_nak {
	uint32_t	nak_sqn;		/* requested sequence number */
	uint16_t	nak_src_nla_afi;	/* nla afi */
	uint16_t	nak_reserved;		/* reserved */
	struct in_addr	nak_src_nla;		/* source nla */
	uint16_t	nak_grp_nla_afi;	/* nla afi */
	uint16_t	nak_reserved2;		/* reserved */
	struct in_addr	nak_grp_nla;		/* multicast group nla */
	/* ... option extension */
};

struct pgm_nak6 {
	uint32_t	nak6_sqn;		/* requested sequence number */
	uint16_t	nak6_src_nla_afi;	/* nla afi */
	uint16_t	nak6_reserved;		/* reserved */
	struct in6_addr nak6_src_nla;	/* source nla */
	uint16_t	nak6_grp_nla_afi;	/* nla afi */
	uint16_t	nak6_reserved2;		/* reserved */
	struct in6_addr nak6_grp_nla;	/* multicast group nla */
	/* ... option extension */
};

/* 9.  Option header (max 16 per packet) */
struct pgm_opt_header {
	uint8_t		opt_type;		/* option type */
#define PGM_OPT_MASK		0x7f
#define PGM_OPT_END		0x80	/* end of options flag */
	uint8_t		opt_length;		/* option length */
	uint8_t		opt_reserved;
#define PGM_OP_ENCODED		0x8	/* F-bit */
#define PGM_OPX_MASK		0x3
#define PGM_OPX_IGNORE		0x0	/* extensibility bits */
#define PGM_OPX_INVALIDATE	0x1
#define PGM_OPX_DISCARD		0x2
#define PGM_OP_ENCODED_NULL	0x80	/* U-bit */
};

/* 9.1.  Option extension length - OPT_LENGTH */
struct pgm_opt_length {
	uint8_t		opt_type;		/* include header as total length overwrites reserved/OPX bits */
	uint8_t		opt_length;
	uint16_t	opt_total_length;	/* total length of all options */
};

/* 9.2.  Option fragment - OPT_FRAGMENT */
struct pgm_opt_fragment {
	uint8_t		opt_reserved;		/* reserved */
	uint32_t	opt_sqn;		/* first sequence number */
	uint32_t	opt_frag_off;		/* offset */
	uint32_t	opt_frag_len;		/* length */
};

/* 9.3.5.  Option NAK List - OPT_NAK_LIST
 *
 * GNU C allows opt_sqn[0], ISO C89 requireqs opt_sqn[1], ISO C99 permits
 * opt_sqn[], but C++11 joins the party with only partial C99 support.
 */
struct pgm_opt_nak_list {
	uint8_t		opt_reserved;		/* reserved */
/* C90 and older */
	uint32_t	opt_sqn[1];		/* requested sequence number [62] */
};

/* 9.4.2.  Option Join - OPT_JOIN */
struct pgm_opt_join {
	uint8_t		opt_reserved;		/* reserved */
	uint32_t	opt_join_min;		/* minimum sequence number */
};

/* 9.5.5.  Option Redirect - OPT_REDIRECT */
struct pgm_opt_redirect {
	uint8_t		opt_reserved;		/* reserved */
	uint16_t	opt_nla_afi;		/* nla afi */
	uint16_t	opt_reserved2;		/* reserved */
	struct in_addr	opt_nla;		/* dlr nla */
};

struct pgm_opt6_redirect {
	uint8_t		opt6_reserved;		/* reserved */
	uint16_t	opt6_nla_afi;		/* nla afi */
	uint16_t	opt6_reserved2;		/* reserved */
	struct in6_addr opt6_nla;		/* dlr nla */
};

/* 9.6.2.  Option Sources - OPT_SYN */
struct pgm_opt_syn {
	uint8_t		opt_reserved;		/* reserved */
};

/* 9.7.4.  Option End Session - OPT_FIN */
struct pgm_opt_fin {
	uint8_t		opt_reserved;		/* reserved */
};

/* 9.8.4.  Option Reset - OPT_RST */
struct pgm_opt_rst {
	uint8_t		opt_reserved;		/* reserved */
};


/*
 * Forward Error Correction - FEC
 */

/* 11.8.1.  Option Parity - OPT_PARITY_PRM */
struct pgm_opt_parity_prm {
	uint8_t		opt_reserved;		/* reserved */
#define PGM_PARITY_PRM_MASK 0x3
#define PGM_PARITY_PRM_PRO  0x1		/* source provides pro-active parity packets */
#define PGM_PARITY_PRM_OND  0x2		/*                 on-demand parity packets */
	uint32_t	parity_prm_tgs;		/* transmission group size */
};

/* 11.8.2.  Option Parity Group - OPT_PARITY_GRP */
struct pgm_opt_parity_grp {
	uint8_t		opt_reserved;		/* reserved */
	uint32_t	prm_group;		/* parity group number */
};

/* 11.8.3.  Option Current Transmission Group Size - OPT_CURR_TGSIZE */
struct pgm_opt_curr_tgsize {
	uint8_t		opt_reserved;		/* reserved */
	uint32_t	prm_atgsize;		/* actual transmission group size */
};

/*
 * Congestion Control
 */

/* 12.7.1.  Option Congestion Report - OPT_CR */
struct pgm_opt_cr {
	uint8_t		opt_reserved;		/* reserved */
#define PGM_OPT_CR_NEL		0x0	/* OPT_CR_NE_WL report */
#define PGM_OPT_CR_NEP		0x1	/* OPT_CR_NE_WP report */
#define PGM_OPT_CR_RXP		0x2	/* OPT_CR_RX_WP report */
	uint32_t	opt_cr_lead;		/* congestion report reference sqn */
	uint16_t	opt_cr_ne_wl;		/* ne worst link */
	uint16_t	opt_cr_ne_wp;		/* ne worst path */
	uint16_t	opt_cr_rx_wp;		/* rcvr worst path */
	uint16_t	opt_reserved2;		/* reserved */
	uint16_t	opt_nla_afi;		/* nla afi */
	uint16_t	opt_reserved3;		/* reserved */
	uint32_t	opt_cr_rcvr;		/* worst receivers nla */
};

/* 12.7.2.  Option Congestion Report Request - OPT_CRQST */
struct pgm_opt_crqst {
	uint8_t		opt_reserved;		/* reserved */
#define PGM_OPT_CRQST_NEL	0x0	/* request OPT_CR_NE_WL report */
#define PGM_OPT_CRQST_NEP	0x1	/* request OPT_CR_NE_WP report */
#define PGM_OPT_CRQST_RXP	0x2	/* request OPT_CR_RX_WP report */
};

/* PGMCC.  ACK Packet */
struct pgm_ack {
	uint32_t	ack_rx_max;		/* RX_MAX */
	uint32_t	ack_bitmap;		/* received packets */
	/* ... option extensions */
};

/* PGMCC  Options */
struct pgm_opt_pgmcc_data {
	uint8_t		opt_reserved;		/* reserved */
	uint32_t	opt_tstamp;		/* timestamp */
	uint16_t	opt_nla_afi;		/* nla afi */
	uint16_t	opt_reserved2;		/* reserved */
	struct in_addr	opt_nla;		/* ACKER nla */
};

struct pgm_opt6_pgmcc_data {
	uint8_t		opt6_reserved;		/* reserved */
	uint32_t	opt6_tstamp;		/* timestamp */
	uint16_t	opt6_nla_afi;		/* nla afi */
	uint16_t	opt6_reserved2;		/* reserved */
	struct in6_addr	opt6_nla;		/* ACKER nla */
};

struct pgm_opt_pgmcc_feedback {
	uint8_t		opt_reserved;		/* reserved */
	uint32_t	opt_tstamp;		/* timestamp */
	uint16_t	opt_nla_afi;		/* nla afi */
	uint16_t	opt_loss_rate;		/* loss rate */
	struct in_addr	opt_nla;		/* ACKER nla */
};

struct pgm_opt6_pgmcc_feedback {
	uint8_t		opt6_reserved;		/* reserved */
	uint32_t	opt6_tstamp;		/* timestamp */
	uint16_t	opt6_nla_afi;		/* nla afi */
	uint16_t	opt6_loss_rate;		/* loss rate */
	struct in6_addr	opt6_nla;		/* ACKER nla */
};


/*
 * SPM Requests
 */

/* 13.6.  SPM Requests */
#if 0
struct pgm_spmr {
    /* ... option extensions */
};
#endif


/*
 * Poll Mechanism
 */

/* 14.7.1.  Poll Request */
struct pgm_poll {
	uint32_t	poll_sqn;		/* poll sequence number */
	uint16_t	poll_round;		/* poll round */
	uint16_t	poll_s_type;		/* poll sub-type */
#define PGM_POLL_GENERAL	0x0	/* general poll  */
#define PGM_POLL_DLR		0x1	/* DLR poll */
	uint16_t	poll_nla_afi;		/* nla afi */
	uint16_t	poll_reserved;		/* reserved */
	struct in_addr	poll_nla;		/* path nla */
	uint32_t	poll_bo_ivl;		/* poll back-off interval */
	char		poll_rand[4];		/* random string */
	uint32_t	poll_mask;		/* matching bit-mask */
    /* ... option extensions */
};

struct pgm_poll6 {
	uint32_t	poll6_sqn;		/* poll sequence number */
	uint16_t	poll6_round;		/* poll round */
	uint16_t	poll6_s_type;		/* poll sub-type */
	uint16_t	poll6_nla_afi;		/* nla afi */
	uint16_t	poll6_reserved;		/* reserved */
	struct in6_addr poll6_nla;		/* path nla */
	uint32_t	poll6_bo_ivl;		/* poll back-off interval */
	char		poll6_rand[4];		/* random string */
	uint32_t	poll6_mask;		/* matching bit-mask */
    /* ... option extensions */
};

/* 14.7.2.  Poll Response */
struct pgm_polr {
	uint32_t	polr_sqn;		/* polr sequence number */
	uint16_t	polr_round;		/* polr round */
	uint16_t	polr_reserved;		/* reserved */
    /* ... option extensions */
};


/*
 * Implosion Prevention
 */

/* 15.4.1.  Option NAK Back-Off Interval - OPT_NAK_BO_IVL */
struct pgm_opt_nak_bo_ivl {
	uint8_t		opt_reserved;		/* reserved */
	uint32_t	opt_nak_bo_ivl;		/* nak back-off interval */
	uint32_t	opt_nak_bo_ivl_sqn;	/* nak back-off interval sqn */
};

/* 15.4.2.  Option NAK Back-Off Range - OPT_NAK_BO_RNG */
struct pgm_opt_nak_bo_rng {
	uint8_t		opt_reserved;		/* reserved */
	uint32_t	opt_nak_max_bo_ivl;	/* maximum nak back-off interval */
	uint32_t	opt_nak_min_bo_ivl;	/* minimum nak back-off interval */
};

/* 15.4.3.  Option Neighbour Unreachable - OPT_NBR_UNREACH */
struct pgm_opt_nbr_unreach {
	uint8_t		opt_reserved;		/* reserved */
};

/* 15.4.4.  Option Path - OPT_PATH_NLA */
struct pgm_opt_path_nla {
	uint8_t		opt_reserved;		/* reserved */
	struct in_addr	opt_path_nla;		/* path nla */
};

struct pgm_opt6_path_nla {
	uint8_t		opt6_reserved;		/* reserved */
	struct in6_addr opt6_path_nla;		/* path nla */
};


#if ((defined( __GNUC__ ) && ( __GNUC__ >= 4 )) && !defined( __sun ) && !defined( __CYGWIN__ )) || defined( __xlc__ ) || defined( __xlC__ )
#	pragma pack(pop)
#else
#	pragma pack()
#endif

#define PGM_IS_UPSTREAM(t) \
	((t) == PGM_NAK 	/* unicast */			\
	 || (t) == PGM_NNAK	/* unicast */			\
	 || (t) == PGM_SPMR	/* multicast + unicast */	\
	 || (t) == PGM_POLR	/* unicast */			\
	 || (t) == PGM_ACK)	/* unicast */

#define PGM_IS_PEER(t) \
	((t) == PGM_SPMR)	/* multicast */

#define PGM_IS_DOWNSTREAM(t) \
	((t) == PGM_SPM		/* all types are multicast */	\
	 || (t) == PGM_ODATA					\
	 || (t) == PGM_RDATA					\
	 || (t) == PGM_POLL					\
	 || (t) == PGM_NCF)


