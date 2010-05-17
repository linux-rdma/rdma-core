/*
 * Copyright (c) 2005-2010 Intel Corporation.  All rights reserved.
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

#if !defined(CMA_H)
#define CMA_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <errno.h>
#include <endian.h>
#include <byteswap.h>

#include <rdma/rdma_cma.h>

#ifdef INCLUDE_VALGRIND
#   include <valgrind/memcheck.h>
#   ifndef VALGRIND_MAKE_MEM_DEFINED
#       warning "Valgrind requested, but VALGRIND_MAKE_MEM_DEFINED undefined"
#   endif
#endif

#ifndef VALGRIND_MAKE_MEM_DEFINED
#   define VALGRIND_MAKE_MEM_DEFINED(addr,len)
#endif

#define PFX "librdmacm: "

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#else
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#endif

#define min(a, b) (a < b ? a : b)

static inline int ERR(int err)
{
	errno = err;
	return -1;
}

int ucma_init();
extern int af_ib_support;

#define RAI_ROUTEONLY 0x01000000

#ifdef USE_IB_ACM
void ucma_ib_init();
void ucma_ib_cleanup();
void ucma_ib_resolve(struct rdma_addrinfo *rai);
#else
#define ucma_ib_init()
#define ucma_ib_cleanup()
#define ucma_ib_resolve(x)
#endif

/* Define path record definition if using older version of libibverbs */
#ifdef DEFINE_PATH_RECORD
#define IBV_PATH_RECORD_REVERSIBLE 0x80

struct ibv_path_record
{
	uint64_t        service_id;
	union ibv_gid   dgid;
	union ibv_gid   sgid;
	uint16_t        dlid;
	uint16_t        slid;
	uint32_t        flowlabel_hoplimit; /* resv-31:28 flow label-27:8 hop limit-7:0*/
	uint8_t         tclass;
	uint8_t         reversible_numpath; /* reversible-7:7 num path-6:0 */
	uint16_t        pkey;
	uint16_t        qosclass_sl;        /* qos class-15:4 sl-3:0 */
	uint8_t         mtu;                /* mtu selector-7:6 mtu-5:0 */
	uint8_t         rate;               /* rate selector-7:6 rate-5:0 */
	uint8_t         packetlifetime;     /* lifetime selector-7:6 lifetime-5:0 */
	uint8_t         preference;
	uint8_t         reserved[6];
};

#define IBV_PATH_FLAG_GMP             (1<<0)
#define IBV_PATH_FLAG_PRIMARY         (1<<1)
#define IBV_PATH_FLAG_ALTERNATE       (1<<2)
#define IBV_PATH_FLAG_OUTBOUND        (1<<3)
#define IBV_PATH_FLAG_INBOUND         (1<<4)
#define IBV_PATH_FLAG_INBOUND_REVERSE (1<<5)
#define IBV_PATH_FLAG_BIDIRECTIONAL   (IBV_PATH_FLAG_OUTBOUND |     \
                                       IBV_PATH_FLAG_INBOUND_REVERSE)

struct ibv_path_data
{
	uint32_t               flags;
	uint32_t               reserved;
	struct ibv_path_record path;
};
#endif

#endif /* CMA_H */
