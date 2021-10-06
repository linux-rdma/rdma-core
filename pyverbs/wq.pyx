# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia Inc. All rights reserved. See COPYING file

from libc.string cimport memcpy

from .pyverbs_error import PyverbsRDMAError
from pyverbs.base import PyverbsRDMAErrno
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
            self.logger.debug('Closing WQ')
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
