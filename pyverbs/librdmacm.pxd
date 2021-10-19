# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved. See COPYING file

include 'libibverbs.pxd'
include 'librdmacm_enums.pxd'
from libc.stdint cimport uint8_t, uint32_t

cdef extern from '<rdma/rdma_cma.h>':

    cdef struct rdma_cm_id:
        ibv_context         *verbs
        rdma_event_channel  *channel
        void                *context
        ibv_qp              *qp
        rdma_port_space     ps
        uint8_t             port_num
        rdma_cm_event       *event
        ibv_comp_channel    *send_cq_channel
        ibv_cq              *send_cq
        ibv_comp_channel    *recv_cq_channel
        ibv_cq              *recv_cq
        ibv_srq             *srq
        ibv_pd              *pd
        ibv_qp_type         qp_type

    cdef struct rdma_event_channel:
        int fd

    cdef struct rdma_conn_param:
        const void *private_data
        uint8_t     private_data_len
        uint8_t     responder_resources
        uint8_t     initiator_depth
        uint8_t     flow_control
        uint8_t     retry_count
        uint8_t     rnr_retry_count
        uint8_t     srq
        uint32_t    qp_num

    cdef struct rdma_ud_param:
        const void  *private_data
        uint8_t     private_data_len
        ibv_ah_attr ah_attr
        uint32_t    qp_num
        uint32_t    qkey

    cdef union param:
        rdma_conn_param conn
        rdma_ud_param   ud

    cdef struct rdma_cm_event:
        rdma_cm_id          *id
        rdma_cm_id          *listen_id
        rdma_cm_event_type  event
        int                 status
        param               param

    cdef struct rdma_addrinfo:
        int             ai_flags
        int             ai_family
        int             ai_qp_type
        int             ai_port_space
        int             ai_src_len
        int             ai_dst_len
        sockaddr        *ai_src_addr
        sockaddr        *ai_dst_addr
        char            *ai_src_canonname
        char            *ai_dst_canonname
        size_t          ai_route_len
        void            *ai_route
        size_t          ai_connect_len
        void            *ai_connect
        rdma_addrinfo   *ai_next

    cdef struct rdma_cm_join_mc_attr_ex:
        uint32_t        comp_mask
        uint32_t        join_flags
        sockaddr        *addr

# These non rdmacm structs defined in one of rdma_cma.h's included header files
    cdef struct sockaddr:
        unsigned short  sa_family
        char            sa_data[14]

    cdef struct in_addr:
        uint32_t s_addr

    cdef struct sockaddr_in:
        short           sin_family
        unsigned short  sin_port
        in_addr         sin_addr
        char            sin_zero[8]

    rdma_event_channel *rdma_create_event_channel()
    void rdma_destroy_event_channel(rdma_event_channel *channel)
    ibv_context **rdma_get_devices(int *num_devices)
    void rdma_free_devices (ibv_context **list);
    int rdma_get_cm_event(rdma_event_channel *channel, rdma_cm_event **event)
    int rdma_ack_cm_event(rdma_cm_event *event)
    char *rdma_event_str(rdma_cm_event_type event)
    int rdma_create_ep(rdma_cm_id **id, rdma_addrinfo *res,
                       ibv_pd *pd, ibv_qp_init_attr *qp_init_attr)
    void rdma_destroy_ep(rdma_cm_id *id)
    int rdma_create_id(rdma_event_channel *channel, rdma_cm_id **id,
                       void *context, rdma_port_space ps)
    int rdma_destroy_id(rdma_cm_id *id)
    int rdma_get_remote_ece(rdma_cm_id *id, ibv_ece *ece)
    int rdma_set_local_ece(rdma_cm_id *id, ibv_ece *ece)
    int rdma_get_request(rdma_cm_id *listen, rdma_cm_id **id)
    int rdma_bind_addr(rdma_cm_id *id, sockaddr *addr)
    int rdma_resolve_addr(rdma_cm_id *id, sockaddr *src_addr,
                          sockaddr *dst_addr, int timeout_ms)
    int rdma_resolve_route(rdma_cm_id *id, int timeout_ms)
    int rdma_join_multicast(rdma_cm_id *id, sockaddr *addr, void *context)
    int rdma_join_multicast_ex(rdma_cm_id *id, rdma_cm_join_mc_attr_ex *mc_join_attr,
                               void *context)
    int rdma_leave_multicast(rdma_cm_id *id, sockaddr *addr)
    int rdma_connect(rdma_cm_id *id, rdma_conn_param *conn_param)
    int rdma_disconnect(rdma_cm_id *id)
    int rdma_listen(rdma_cm_id *id, int backlog)
    int rdma_accept(rdma_cm_id *id, rdma_conn_param *conn_param)
    int rdma_establish(rdma_cm_id *id)
    int rdma_getaddrinfo(char *node, char *service, rdma_addrinfo *hints,
                         rdma_addrinfo **res)
    void rdma_freeaddrinfo(rdma_addrinfo *res)
    int rdma_init_qp_attr(rdma_cm_id *id, ibv_qp_attr *qp_attr,
                          int *qp_attr_mask)
    int rdma_create_qp(rdma_cm_id *id, ibv_pd *pd,
                       ibv_qp_init_attr *qp_init_attr)
    void rdma_destroy_qp(rdma_cm_id *id)
    int rdma_set_option(rdma_cm_id *id, int level, int optname,
                        void *optval, size_t optlen)
    int rdma_reject(rdma_cm_id *id, const void *private_data, uint8_t private_data_len)

cdef extern from '<rdma/rdma_verbs.h>':
    int rdma_post_recv(rdma_cm_id *id, void *context, void *addr,
                       size_t length, ibv_mr *mr)
    int rdma_post_send(rdma_cm_id *id, void *context, void *addr,
                       size_t length, ibv_mr *mr, int flags)
    int rdma_post_ud_send(rdma_cm_id *id, void *context, void *addr,
                          size_t length, ibv_mr *mr, int flags, ibv_ah *ah,
                          uint32_t remote_qpn)
    int rdma_post_read(rdma_cm_id *id, void *context, void *addr,
                       size_t length, ibv_mr *mr, int flags,
                       uint64_t remote_addr, uint32_t rkey)
    int rdma_post_write(rdma_cm_id *id, void *context, void *addr,
                        size_t length, ibv_mr *mr, int flags,
                        uint64_t remote_addr, uint32_t rkey)
    int rdma_get_send_comp(rdma_cm_id *id, ibv_wc *wc)
    int rdma_get_recv_comp(rdma_cm_id *id, ibv_wc *wc)
    ibv_mr *rdma_reg_msgs(rdma_cm_id *id, void *addr, size_t length)
    ibv_mr *rdma_reg_read(rdma_cm_id *id, void *addr, size_t length)
    ibv_mr *rdma_reg_write(rdma_cm_id *id, void *addr, size_t length)
    int rdma_dereg_mr(ibv_mr *mr)
