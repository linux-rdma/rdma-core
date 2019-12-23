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

    int rdma_create_ep(rdma_cm_id **id, rdma_addrinfo *res,
                       ibv_pd *pd, ibv_qp_init_attr *qp_init_attr)
    void rdma_destroy_ep(rdma_cm_id *id)
    int rdma_get_request(rdma_cm_id *listen, rdma_cm_id **id)
    int rdma_connect(rdma_cm_id *id, rdma_conn_param *conn_param)
    int rdma_disconnect(rdma_cm_id *id)
    int rdma_listen(rdma_cm_id *id, int backlog)
    int rdma_accept(rdma_cm_id *id, rdma_conn_param *conn_param)
    int rdma_getaddrinfo(char *node, char *service, rdma_addrinfo *hints,
                         rdma_addrinfo **res)
    void rdma_freeaddrinfo(rdma_addrinfo *res)

cdef extern from '<rdma/rdma_verbs.h>':
    int rdma_post_recv(rdma_cm_id *id, void *context, void *addr,
                       size_t length, ibv_mr *mr)
    int rdma_post_send(rdma_cm_id *id, void *context, void *addr,
                       size_t length, ibv_mr *mr, int flags)
    int rdma_get_send_comp(rdma_cm_id *id, ibv_wc *wc)
    int rdma_get_recv_comp(rdma_cm_id *id, ibv_wc *wc)
    ibv_mr *rdma_reg_msgs(rdma_cm_id *id, void *addr, size_t length)
    int rdma_dereg_mr(ibv_mr *mr)
