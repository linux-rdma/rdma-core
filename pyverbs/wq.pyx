# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia Inc. All rights reserved. See COPYING file

from libc.stdlib cimport calloc, free
from libc.stdint cimport uint8_t
from libc.string cimport memcpy
import weakref

from .pyverbs_error import PyverbsRDMAError, PyverbsError, PyverbsUserError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
cimport pyverbs.libibverbs_enums as e
from pyverbs.device cimport Context
from pyverbs.wr cimport RecvWR
from pyverbs.cq cimport CQ
from pyverbs.pd cimport PD
from pyverbs.qp cimport QP


cdef class WQInitAttr(PyverbsObject):
    def __init__(self, wq_context=None, PD wq_pd=None, CQ wq_cq=None, wq_type=e.IBV_WQT_RQ,
                 max_wr=100, max_sge=1, comp_mask=0, create_flags=0):
        """
        Initializes a WqInitAttr object representing ibv_wq_init_attr struct.
        :param wq_context: Associated WQ context
        :param wq_pd: PD to be associated with the WQ
        :param wq_cq: CQ to be associated with the WQ
        :param wp_type: The desired WQ type
        :param max_wr: Requested max number of outstanding WRs in the WQ
        :param max_sge: Requested max number of scatter/gather (s/g) elements per WR in the WQ
        :param comp_mask: Identifies valid fields
        :param create_flags: Creation flags for the WQ
        :return: A WqInitAttr object
        """
        super().__init__()
        self.attr.wq_context = <void*>(wq_context) if wq_context else NULL
        self.attr.wq_type = wq_type
        self.attr.max_wr = max_wr
        self.attr.max_sge = max_sge
        self.pd = wq_pd
        self.attr.pd = wq_pd.pd if wq_pd else NULL
        self.cq = wq_cq
        self.attr.cq = wq_cq.cq if wq_cq else NULL
        self.attr.comp_mask = comp_mask
        self.attr.create_flags = create_flags

    @property
    def wq_type(self):
        return self.attr.wq_type
    @wq_type.setter
    def wq_type(self, val):
        self.attr.wq_type = val

    @property
    def pd(self):
        return self.pd
    @pd.setter
    def pd(self, PD val):
        self.pd = val
        self.attr.pd = <v.ibv_pd*>val.pd

    @property
    def cq(self):
        return self.cq
    @cq.setter
    def cq(self, CQ val):
        self.cq = val
        self.attr.cq = <v.ibv_cq*>val.cq


cdef class WQAttr(PyverbsObject):
    def __init__(self, attr_mask=0, wq_state=0, curr_wq_state=0, flags=0, flags_mask=0):
        """
        Initializes a WQAttr object which represents ibv_wq_attr struct. It
        can be used to modify a WQ.
        :param attr_mask: Identifies valid fields
        :param wq_state: Desired WQ state
        :param curr_wq_state: Current WQ state
        :param flags: Flags values to modify
        :param flags_mask: Which flags to modify
        :return: An initialized WQAttr object
        """
        super().__init__()
        self.attr.attr_mask = attr_mask
        self.attr.wq_state = wq_state
        self.attr.curr_wq_state = curr_wq_state
        self.attr.flags = flags
        self.attr.flags_mask = flags_mask

    @property
    def wq_state(self):
        return self.attr.wq_state
    @wq_state.setter
    def wq_state(self, val):
        self.attr.wq_state = val

    @property
    def attr_mask(self):
        return self.attr.attr_mask
    @attr_mask.setter
    def attr_mask(self, val):
        self.attr.attr_mask = val

    @property
    def curr_wq_state(self):
        return self.attr.curr_wq_state
    @curr_wq_state.setter
    def curr_wq_state(self, val):
        self.attr.curr_wq_state = val

    @property
    def flags(self):
        return self.attr.flags
    @flags.setter
    def flags(self, val):
        self.attr.flags = val

    @property
    def flags_mask(self):
        return self.attr.flags_mask
    @flags_mask.setter
    def flags_mask(self, val):
        self.attr.flags_mask = val


cdef class WQ(PyverbsCM):
    def __init__(self, Context ctx, WQInitAttr attr):
        """
        Creates a WQ object.
        :param ctx: The context the wq will be associated with.
        :param attr: WQ initial attributes of type WQInitAttr.
        :return: A WQ object
        """
        super().__init__()
        self.wq = v.ibv_create_wq(ctx.context, &attr.attr)
        if self.wq == NULL:
            raise PyverbsRDMAErrno('Failed to create WQ')
        self.context = ctx
        ctx.add_ref(self)
        pd = <PD>attr.pd
        pd.add_ref(self)
        self.pd = pd
        cq = <CQ>attr.cq
        cq.add_ref(self)
        self.cq = cq
        self.rwq_ind_tables = weakref.WeakSet()

    cpdef add_ref(self, obj):
        if isinstance(obj, RwqIndTable):
            self.rwq_ind_tables.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def modify(self, WQAttr wq_attr not None):
        """
        Modify the WQ
        :param qp_attr: A WQAttr object with updated values to be applied to
                        the WQ
        :return: None
        """
        rc = v.ibv_modify_wq(self.wq, &wq_attr.attr)
        if rc != 0:
            raise PyverbsRDMAError('Failed to modify WQ', rc)

    def post_recv(self, RecvWR wr not None, RecvWR bad_wr=None):
        """
        Post a receive WR on the WQ.
        :param wr: The work request to post
        :param bad_wr: A RecvWR object to hold the bad WR if it is available in
                       case of a failure
        :return: None
        """
        cdef v.ibv_recv_wr *my_bad_wr
        # In order to provide a pointer to a pointer, use a temporary cdef'ed
        # variable.
        rc = v.ibv_post_wq_recv(self.wq, &wr.recv_wr, &my_bad_wr)
        if rc != 0:
            if (bad_wr):
                memcpy(&bad_wr.recv_wr, my_bad_wr, sizeof(bad_wr.recv_wr))
            raise PyverbsRDMAError('Failed to post recv', rc)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        """
        Closes the underlying C object of the WQ.
        :return: None
        """
        if self.wq != NULL:
            if self.logger:
                self.logger.debug('Closing WQ')
            close_weakrefs([self.rwq_ind_tables])
            rc = v.ibv_destroy_wq(self.wq)
            if rc != 0:
                raise PyverbsRDMAError('Failed to dealloc WQ', rc)
            self.wq = NULL
            self.context = None
            self.pd = None
            self.cq = None

    @property
    def wqn(self):
        return self.wq.wq_num


cdef class RwqIndTableInitAttr(PyverbsObject):
    def __init__(self, log_ind_tbl_size=5, wqs_list=None, comp_mask=0):
        """
        Initializes a RwqIndTableInitAttr object representing ibv_rwq_ind_table_init_attr struct.
        :param log_ind_tbl_size: Log, base 2, of Indirection table size
        :param wqs_list: List of WQs
        :param comp_mask: Identifies valid fields
        :return: A RwqIndTableInitAttr object
        """
        super().__init__()
        if log_ind_tbl_size <= 0:
            raise PyverbsUserError('Invalid indirection table size. Log size must be > 0')
        if (1 << log_ind_tbl_size) < len(wqs_list):
            raise PyverbsUserError(f'Requested table size ({1 << log_ind_tbl_size}) is smaller '
                                   f'than the number of wqs ({len(wqs_list)})')
        self.attr.log_ind_tbl_size = log_ind_tbl_size
        cdef v.ibv_wq **rwq_ind_table = <v.ibv_wq **>calloc(len(wqs_list), sizeof(v.ibv_wq*))
        if rwq_ind_table == NULL:
            raise MemoryError('Failed to allocate memory for Indirection Table')
        for i in range(len(wqs_list)):
            rwq_ind_table[i] = (<WQ>wqs_list[i]).wq
        self.attr.ind_tbl = rwq_ind_table
        self.wqs_list = wqs_list
        self.attr.comp_mask = comp_mask

    def __dealloc__(self):
        """
        Closes the rwq_ind_tbl init attr.
        :return: None
        """
        free(self.attr.ind_tbl)


cdef class RwqIndTable(PyverbsCM):
    def __init__(self, Context ctx, RwqIndTableInitAttr attr):
        """
        Initializes a RwqIndTable object.
        :param ctx: The context the RWQ IND TBL will be associated with.
        :param attr: RWQ IND TBL initial attributes of type RwqIndTableInitAttr.
        :return: A RwqIndTable object
        """
        super().__init__()
        self.rwq_ind_table = v.ibv_create_rwq_ind_table(ctx.context, &attr.attr)
        if self.rwq_ind_table == NULL:
            raise PyverbsRDMAErrno('Failed to create RwqIndTable')
        self.context = ctx
        ctx.add_ref(self)
        self.wqs = attr.wqs_list
        for wq in self.wqs:
            wq.add_ref(self)
        self.qps = weakref.WeakSet()

    cpdef add_ref(self, obj):
        if isinstance(obj, QP):
            self.qps.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    @property
    def wqs(self):
        return self.wqs

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        """
        Closes the underlying C object of the RWQ IND TBL.
        :return: None
        """
        if self.rwq_ind_table != NULL:
            if self.logger:
                self.logger.debug('Closing RWQ IND TBL')
            close_weakrefs([self.qps])
            rc = v.ibv_destroy_rwq_ind_table(self.rwq_ind_table)
            if rc != 0:
                raise PyverbsRDMAError('Failed to dealloc RWQ IND TBL', rc)
            self.rwq_ind_table = NULL
            self.context = None


cdef class RxHashConf(PyverbsObject):
    def __init__(self, rx_hash_function=0, rx_hash_key_len=0,
                 rx_hash_key=None, rx_hash_fields_mask=0):
        """
        Initializes a RxHashConf object representing ibv_rx_hash_conf struct.
        :param rx_hash_function: RX hash function, use enum ibv_rx_hash_function_flags
        :param rx_hash_key_len: RX hash key length
        :param rx_hash_key: RX hash key data
        :param rx_hash_fields_mask: RX fields that should participate in the hashing
        :return: A RxHashConf object
        """
        super().__init__()
        cdef uint8_t *rx_hash_key_c = NULL
        if rx_hash_key:
            if rx_hash_key_len != len(rx_hash_key):
                raise PyverbsUserError('Length of rx_hash_key not equal to rx_hash_key_len')
            self.rx_hash_key = rx_hash_key
        self.rx_hash_conf.rx_hash_function = rx_hash_function
        self.rx_hash_conf.rx_hash_key_len = rx_hash_key_len
        self.rx_hash_conf.rx_hash_fields_mask = rx_hash_fields_mask

    @property
    def rx_hash_function(self):
        return self.rx_hash_conf.rx_hash_function
    @rx_hash_function.setter
    def rx_hash_function(self, val):
        self.rx_hash_conf.rx_hash_function = val

    @property
    def rx_hash_key_len(self):
        return self.rx_hash_conf.rx_hash_key_len
    @rx_hash_key_len.setter
    def rx_hash_key_len(self, val):
        if val <= 0:
            raise PyverbsUserError('Invalid rx_hash_key_len. Must be greater then 0')
        self.rx_hash_conf.rx_hash_key_len = val

    @property
    def rx_hash_fields_mask(self):
        return self.rx_hash_conf.rx_hash_fields_mask
    @rx_hash_fields_mask.setter
    def rx_hash_fields_mask(self, val):
        self.rx_hash_conf.rx_hash_fields_mask = val

    @property
    def rx_hash_key(self):
        return self.rx_hash_conf.rx_hash_fields_mask
    @rx_hash_key.setter
    def rx_hash_key(self, vals_list):
        if self.rx_hash_conf.rx_hash_key != NULL:
            free(self.rx_hash_conf.rx_hash_key)
            self.rx_hash_conf.rx_hash_key = NULL
        cdef uint8_t *rx_hash_key_c = <uint8_t*>calloc(len(vals_list), sizeof(uint8_t))
        if rx_hash_key_c == NULL:
            raise MemoryError('Failed to allocate memory for RX hash key')
        for i in range(len(vals_list)):
            rx_hash_key_c[i] = vals_list[i]
        self.rx_hash_conf.rx_hash_key = rx_hash_key_c
        self.rx_hash_conf.rx_hash_key_len = len(vals_list)

    def __dealloc__(self):
        """
        Frees rx hash key allocated memory.
        :return: None
        """
        free(self.rx_hash_conf.rx_hash_key)
        self.rx_hash_conf.rx_hash_key = NULL
