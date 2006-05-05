/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2005-2006 Intel Corporation.  All rights reserved.
 *
 * This Software is licensed under one of the following licenses:
 *
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/cpl.php.
 *
 * 2) under the terms of the "The BSD License" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 *
 * 3) under the terms of the "GNU General Public License (GPL) Version 2" a
 *    copy of which is available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/gpl-license.php.
 *
 * Licensee has the right to choose one of the above licenses.
 *
 * Redistributions of source code must retain the above copyright
 * notice and one of the license notices.
 *
 * Redistributions in binary form must reproduce both the above copyright
 * notice, one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 *
 */

#if !defined(RDMA_CMA_H)
#define RDMA_CMA_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <infiniband/verbs.h>
#include <infiniband/sa.h>

/*
 * Upon receiving a device removal event, users must destroy the associated
 * RDMA identifier and release all resources allocated with the device.
 */
enum rdma_cm_event_type {
	RDMA_CM_EVENT_ADDR_RESOLVED,
	RDMA_CM_EVENT_ADDR_ERROR,
	RDMA_CM_EVENT_ROUTE_RESOLVED,
	RDMA_CM_EVENT_ROUTE_ERROR,
	RDMA_CM_EVENT_CONNECT_REQUEST,
	RDMA_CM_EVENT_CONNECT_RESPONSE,
	RDMA_CM_EVENT_CONNECT_ERROR,
	RDMA_CM_EVENT_UNREACHABLE,
	RDMA_CM_EVENT_REJECTED,
	RDMA_CM_EVENT_ESTABLISHED,
	RDMA_CM_EVENT_DISCONNECTED,
	RDMA_CM_EVENT_DEVICE_REMOVAL,
};

/* Protocol levels for get/set options. */
enum {
	RDMA_PROTO_IP = 0,
	RDMA_PROTO_IB = 1,
};

/* IB specific option names for get/set. */
enum {
	IB_PATH_OPTIONS = 1,
};

struct ib_addr {
	union ibv_gid	sgid;
	union ibv_gid	dgid;
	uint16_t	pkey;
};

struct rdma_addr {
	struct sockaddr_in6	src_addr;
	struct sockaddr_in6	dst_addr;
	union {
		struct ib_addr	ibaddr;
	} addr;
};

struct rdma_route {
	struct rdma_addr	 addr;
	struct ib_sa_path_rec	*path_rec;
	int			 num_paths;
};

struct rdma_cm_id {
	struct ibv_context	*verbs;
	void			*context;
	struct ibv_qp		*qp;
	struct rdma_route	 route;
	uint8_t			 port_num;
};

struct rdma_cm_event {
	struct rdma_cm_id	*id;
	struct rdma_cm_id	*listen_id;
	enum rdma_cm_event_type	 event;
	int			 status;
	void			*private_data;
	uint8_t			 private_data_len;
};

int rdma_create_id(struct rdma_cm_id **id, void *context);

int rdma_destroy_id(struct rdma_cm_id *id);

/**
 * rdma_bind_addr - Bind an RDMA identifier to a source address and
 *   associated RDMA device, if needed.
 *
 * @id: RDMA identifier.
 * @addr: Local address information.  Wildcard values are permitted.
 *
 * This associates a source address with the RDMA identifier before calling
 * rdma_listen.  If a specific local address is given, the RDMA identifier will
 * be bound to a local RDMA device.
 */
int rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr);

/**
 * rdma_resolve_addr - Resolve destination and optional source addresses
 *   from IP addresses to an RDMA address.  If successful, the specified
 *   rdma_cm_id will be bound to a local device.
 *
 * @id: RDMA identifier.
 * @src_addr: Source address information.  This parameter may be NULL.
 * @dst_addr: Destination address information.
 * @timeout_ms: Time to wait for resolution to complete.
 */
int rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      struct sockaddr *dst_addr, int timeout_ms);

/**
 * rdma_resolve_route - Resolve the RDMA address bound to the RDMA identifier
 *   into route information needed to establish a connection.
 *
 * This is called on the client side of a connection.
 * Users must have first called rdma_resolve_addr to resolve a dst_addr
 * into an RDMA address before calling this routine.
 */
int rdma_resolve_route(struct rdma_cm_id *id, int timeout_ms);

/**
 * rdma_create_qp - Allocate a QP and associate it with the specified RDMA
 * identifier.
 *
 * QPs allocated to an rdma_cm_id will automatically be transitioned by the CMA
 * through their states.
 */
int rdma_create_qp(struct rdma_cm_id *id, struct ibv_pd *pd,
		   struct ibv_qp_init_attr *qp_init_attr);

/**
 * rdma_destroy_qp - Deallocate the QP associated with the specified RDMA
 * identifier.
 *
 * Users must destroy any QP associated with an RDMA identifier before
 * destroying the RDMA ID.
 */
void rdma_destroy_qp(struct rdma_cm_id *id);

struct rdma_conn_param {
	const void *private_data;
	uint8_t private_data_len;
	uint8_t responder_resources;
	uint8_t initiator_depth;
	uint8_t flow_control;
	uint8_t retry_count;		/* ignored when accepting */
	uint8_t rnr_retry_count;
};

/**
 * rdma_connect - Initiate an active connection request.
 *
 * Users must have resolved a route for the rdma_cm_id to connect with
 * by having called rdma_resolve_route before calling this routine.
 */
int rdma_connect(struct rdma_cm_id *id, struct rdma_conn_param *conn_param);

/**
 * rdma_listen - This function is called by the passive side to
 *   listen for incoming connection requests.
 *
 * Users must have bound the rdma_cm_id to a local address by calling
 * rdma_bind_addr before calling this routine.
 */
int rdma_listen(struct rdma_cm_id *id, int backlog);

/**
 * rdma_accept - Called to accept a connection request.
 * @id: Connection identifier associated with the request.
 * @conn_param: Information needed to establish the connection.
 */
int rdma_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param);

/**
 * rdma_reject - Called on the passive side to reject a connection request.
 */
int rdma_reject(struct rdma_cm_id *id, const void *private_data,
		uint8_t private_data_len);

/**
 * rdma_disconnect - This function disconnects the associated QP.
 */
int rdma_disconnect(struct rdma_cm_id *id);

/**
 * rdma_get_cm_event - Retrieves the next pending communications event,
 *   if no event is pending waits for an event.
 * @event: Allocated information about the next communication event.
 *    Event should be freed using rdma_ack_cm_event()
 *
 * A RDMA_CM_EVENT_CONNECT_REQUEST communication events result 
 * in the allocation of a new @rdma_cm_id. 
 * Clients are responsible for destroying the new @rdma_cm_id.
 */
int rdma_get_cm_event(struct rdma_cm_event **event);

/**
 * rdma_ack_cm_event - Free a communications event.
 * @event: Event to be released.
 *
 * All events which are allocated by rdma_get_cm_event() must be released,
 * there should be a one-to-one correspondence between successful gets
 * and acks.
 */
int rdma_ack_cm_event(struct rdma_cm_event *event);

int rdma_get_fd(void);

/**
 * rdma_get_option - Retrieve options for an rdma_cm_id.
 * @id: Communication identifier to retrieve option for.
 * @level: Protocol level of the option to retrieve.
 * @optname: Name of the option to retrieve.
 * @optval: Buffer to receive the returned options.
 * @optlen: On input, the size of the %optval buffer.  On output, the
 *   size of the returned data.
 */
int rdma_get_option(struct rdma_cm_id *id, int level, int optname,
		    void *optval, size_t *optlen);

/**
 * rdma_set_option - Set options for an rdma_cm_id.
 * @id: Communication identifier to set option for.
 * @level: Protocol level of the option to set.
 * @optname: Name of the option to set.
 * @optval: Reference to the option data.
 * @optlen: The size of the %optval buffer.
 */
int rdma_set_option(struct rdma_cm_id *id, int level, int optname,
		    void *optval, size_t optlen);

#endif /* RDMA_CMA_H */
