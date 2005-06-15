/*
 * Copyright (c) 2004,2005 Voltaire Inc.  All rights reserved.
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
 *
 * $Id$
 */

#if !defined( AT_H )
#define AT_H

#include <infiniband/verbs.h>
#include <infiniband/sa.h>

enum ib_at_multipathing_type {
	IB_AT_PATH_SAME_PORT	= 0,
	IB_AT_PATH_SAME_HCA	= 1,		/* but different ports if applicable */
	IB_AT_PATH_SAME_SYSTEM	= 2,		/* but different ports if applicable */
	IB_AT_PATH_INDEPENDENT_HCA = 3,
	IB_AT_PATH_SRC_ROUTE	= 4,		/* application controlled multipathing */
};

enum ib_at_route_flags {
	IB_AT_ROUTE_USE_DEFAULTS	= 0,
	IB_AT_ROUTE_FORCE_ATS		= 1,
	IB_AT_ROUTE_FORCE_ARP		= 2,
	IB_AT_ROUTE_FORCE_RESOLVE	= 4,
};

struct ib_at_path_attr {
	uint16_t qos_tag;
	uint16_t pkey;
	uint8_t multi_path_type;
};

struct ib_at_ib_route {
	union ibv_gid sgid;
	union ibv_gid dgid;
	struct ibv_device *out_dev;
	int out_port;
	struct ib_at_path_attr attr;
};

enum ib_at_op_status {
	IB_AT_STATUS_INVALID	= 0,
	IB_AT_STATUS_PENDING	= 1,
	IB_AT_STATUS_COMPLETED	= 2,
	IB_AT_STATUS_ERROR	= 3,
	IB_AT_STATUS_CANCELED	= 4,
};

/*
 * ib_at_completion structure - callback function parameters structure
 * @completion: completion call back function
 * @context: user defined context pointer
 * @req_id: asynchronous request ID - optional, out
 *
 * The following asynchronous resolution function behavior is as follows:
 *	If the resolve operation can be fulfilled immediately, then the output
 *	structures are set and the number of filled structures is returned.
 *
 *	If the resolve operation cannot by fulfilled immediately and 
 *	an ib_at_completion structure is not provided,
 *	then the function immediately returns -EWOULDBLOCK.
 *
 * 	If ib_at_completion structure is provided and an asynchronous 
 *	operation is started, the function immediately returns zero,
 *	and the request ID field (req_id) is set if the pointer is
 *	non NULL. This request ID may be used to cancel the operation,
 *	or to poll its status.
 *
 *	When an asynchronous operation completes (successfully or not), 
 *	the callback function is called, passing the request ID, 
 *	the supplied user context and the number of output structures.
 *	If the asynchronous operation did not complete, a negative 
 *	error code is return as the 'rec_num'.
 *	Valid error codes are:
 *		-EINTR: operation is canceled
 *		-EIO:	request send failed
 *		-ETIMEOUT: operation timed out
 *
 *	Returned value of zero records means that the resolution process
 *	completed, but the given address could not be resolved at this time.
 */
struct ib_at_completion {
	void (*fn)(uint64_t req_id, void *context, int rec_num);
	void *context;
	uint64_t req_id;
};

/**
 * ib_at_route_by_ip - asynchronously resolve ip route to ib route
 * @dst_ip: destination ip
 * @src_ip: source ip - optional
 * @tos: ip type of service
 * @flags: ib_at_route_flags
 * @ib_route: out structure
 * @async_comp: asynchronous callback structure - optional
 *
 * Resolve the specified dst_ip to a &struct ib_route structure.
 * src_ip can be provide to force specific output interface.
 * flags can be used to select resolving method; currently IB-ARP or ATS.
 *
 * See ib_at_completion structure documentation for asynchronous
 * operation details.
 */
int ib_at_route_by_ip(uint32_t dst_ip, uint32_t src_ip, int tos, uint16_t flags,
		     struct ib_at_ib_route *ib_route,
		     struct ib_at_completion *async_comp);

/**
 * ib_at_paths_by_route - asynchronously resolve ib route to ib path records
 * @ib_route: ib route to resolve
 * @mpath_type: ib_at_multipathing_type
 * @path_arr: SA path record array - out
 * @npath: maximal number of paths to return
 * @async_comp: asynchronous callback structure - optional
 * @req_id: pointer for request ID
 *
 * Resolve the specified ib_route to a SA path record array.
 * Number of returned paths will not exceed npath.
 * Multipathing type may be used to obtain redundant paths for APM,
 * other failover schemes, bandwidth aggregation or source based routing.
 * Note that multipathing request is meaningless unless npath is greater than 1.
 *
 * Returned ib_route structure includes the recommended pkey and qos_tag for
 * this route.
 *
 * See ib_at_completion structure documentation for asynchronous operation
 * details.
 */
int ib_at_paths_by_route(struct ib_at_ib_route *ib_route, uint32_t mpath_type,
			struct ib_sa_path_rec *path_arr, int npath,
			struct ib_at_completion *async_comp, uint64_t *req_id);

/**
 * ib_at_ips_by_gid - asynchronously resolve GID to IP addresses
 * @gid: GID to resolve
 * @dst_ips: array of IPs, out
 * @nips: number of IP entries in dst_ips array
 * @async_comp: asynchronous callback structure - optional
 *
 * Resolve the gid to IP addresses, but not more than nips.
 * This function rely on the IB-ATS mechanism.
 *
 * See ib_at_completion structure documentation for asynchronous
 * operation details.
 */
int ib_at_ips_by_gid(union ibv_gid *gid, uint32_t *dst_ips, int nips,
		    struct ib_at_completion *async_comp);

/**
 * ib_at_ips_by_subnet - return local IP addresses by IP subnet
 * @network: network to resolve - optional
 * @netmask: subnet net mask - optional
 * @dst_ips: array of IPs, out
 * @nips: number of IP entries in dst_ips array
 *
 * Return local IP addresses matching the network and netmask,
 * but not more than nips.
 * 
 * Note that network and netmask as 0x0 or 0xffffffff returns all local IPs.
 */
int ib_at_ips_by_subnet(uint32_t network, uint32_t netmask,
			uint32_t *dst_ips, int nips);

/**
 * ib_at_invalidate_paths - invalidate possibly cached paths keyed by ib_route
 * @ib_route: paths key - optional
 *
 * Returns number of invalidated paths.
 * If ib_route is NULL, then the entire cache will be flushed.
 */
int ib_at_invalidate_paths(struct ib_at_ib_route *ib_route);

/**
 * ib_at_cancel - cancel possible active asynchronous operation
 * @req_id: asynchronous request ID
 *
 * Return 0 if canceled, -1 if cancel failed (e.g. bad ID)
 */
int ib_at_cancel(uint64_t req_id);

/**
 * ib_at_status - poll asynchronous operation's status
 * @req_id: asynchronous request ID ib_at_op_status
 *
 * Return non-negative ib_at_op_status value, 
 * or -EINVAL if the request ID is invalid.
 */
int ib_at_status(uint64_t req_id);

/**
 * ib_at_callback_get - Retrieves the next pending AT callback,
 *   if no callback is pending waits for a callback event.
 */
int ib_at_callback_get();

/**
 * ib_at_get_fd - Returns the file descriptor which AT uses to
 *   submit requests and retrieve callback events.
 *
 * The primary use of the file descriptor is to test for AT readiness
 * events. When the AT becomes ready to READ there is a pending event
 * ready, and a subsequent call to ib_at_event_get will not block.
 * Note: The user should not read or write directly to the AT file
 *       descriptor, it will likely result in an error or unexpected
 *       results.
 */
int ib_at_get_fd(void);

#endif /* IB_AT_H */
