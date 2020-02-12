from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.device cimport Context
from pyverbs.cq cimport CQEX, CQ
from pyverbs.xrcd cimport XRCD
from pyverbs.wr cimport RecvWR
from pyverbs.pd cimport PD
from libc.errno cimport errno
from libc.string cimport memcpy


cdef class SrqAttr(PyverbsObject):
    def __init__(self, max_wr=100, max_sge=1, srq_limit=0):
        super().__init__()
        self.attr.max_wr = max_wr
        self.attr.max_sge = max_sge
        self.attr.srq_limit = srq_limit

    @property
    def max_wr(self):
        return self.attr.max_wr
    @max_wr.setter
    def max_wr(self, val):
        self.attr.max_wr = val

    @property
    def max_sge(self):
        return self.attr.max_sge
    @max_sge.setter
    def max_sge(self, val):
        self.attr.max_sge = val

    @property
    def srq_limit(self):
        return self.attr.srq_limit
    @srq_limit.setter
    def srq_limit(self, val):
        self.attr.srq_limit = val


cdef class SrqInitAttr(PyverbsObject):
    def __init__(self, SrqAttr attr = None):
        super().__init__()
        if attr is not None:
            self.attr.attr.max_wr = attr.max_wr
            self.attr.attr.max_sge = attr.max_sge
            self.attr.attr.srq_limit = attr.srq_limit

    @property
    def max_wr(self):
        return self.attr.attr.max_wr

    @property
    def max_sge(self):
        return self.attr.attr.max_sge

    @property
    def srq_limit(self):
        return self.attr.attr.srq_limit


cdef class SrqInitAttrEx(PyverbsObject):
    def __init__(self, max_wr=100, max_sge=1, srq_limit=0):
        super().__init__()
        self.attr.attr.max_wr = max_wr
        self.attr.attr.max_sge = max_sge
        self.attr.attr.srq_limit = srq_limit
        self._cq = None
        self._pd = None
        self._xrcd = None

    @property
    def max_wr(self):
        return self.attr.attr.max_wr

    @property
    def max_sge(self):
        return self.attr.attr.max_sge

    @property
    def srq_limit(self):
        return self.attr.attr.srq_limit

    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val

    @property
    def srq_type(self):
        return self.attr.srq_type
    @srq_type.setter
    def srq_type(self, val):
        self.attr.srq_type = val

    @property
    def pd(self):
        return self._pd
    @pd.setter
    def pd(self, PD val):
        self._pd = val
        self.attr.pd = val.pd

    @property
    def xrcd(self):
        return self._xrcd
    @xrcd.setter
    def xrcd(self, XRCD val):
        self._xrcd = val
        self.attr.xrcd = val.xrcd

    @property
    def cq(self):
        return self._cq
    @cq.setter
    def cq(self, val):
        if type(val) == CQ:
            self.attr.cq = (<CQ>val).cq
            self._cq = val
        else:
            self.attr.cq = (<CQEX>val).ibv_cq
            self._cq = val


cdef class SRQ(PyverbsCM):
    def __init__(self, object creator not None, object attr not None):
        super().__init__()
        self.srq = NULL
        self.cq = None
        if isinstance(creator, PD):
            self._create_srq(creator, attr)
        elif type(creator) == Context:
            self._create_srq_ex(creator, attr)
        else:
            raise PyverbsRDMAError('Srq needs either Context or PD for creation')
        if self.srq == NULL:
            raise PyverbsRDMAErrno('Failed to create SRQ (errno is {err})'.
                                   format(err=errno))
        self.logger.debug('SRQ Created')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing SRQ')
        if self.srq != NULL:
            rc = v.ibv_destroy_srq(self.srq)
            if rc != 0:
                raise PyverbsRDMAErrno('Failed to destroy SRQ (errno is {err})'.
                                        format(err=errno))
            self.srq = NULL
            self.cq =None

    def _create_srq(self, PD pd, SrqInitAttr init_attr):
        self.srq = v.ibv_create_srq(pd.pd, &init_attr.attr)

    def _create_srq_ex(self, Context context, SrqInitAttrEx init_attr_ex):
        self.srq = v.ibv_create_srq_ex(context.context, &init_attr_ex.attr)
        if init_attr_ex.cq:
            cq = <CQ>init_attr_ex.cq
            cq.add_ref(self)
            self.cq = cq
        if init_attr_ex.xrcd:
            xrcd = <XRCD>init_attr_ex.xrcd
            xrcd.add_ref(self)
        if init_attr_ex.pd:
            pd = <PD>init_attr_ex.pd
            pd.add_ref(self)

    def get_srq_num(self):
        cdef unsigned int srqn
        rc = v.ibv_get_srq_num(self.srq, &srqn)
        if rc != 0:
           raise PyverbsRDMAErrno('Failed to retrieve SRQ number (returned {rc})'.
                                   format(rc=rc))
        return srqn

    def modify(self, SrqAttr attr, comp_mask):
        rc = v.ibv_modify_srq(self.srq, &attr.attr, comp_mask)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to modify SRQ ({err})'.
                                   format(err=errno))

    def query(self):
        attr = SrqAttr()
        rc = v.ibv_query_srq(self.srq, &attr.attr)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to query SRQ ({err})'.
                                   format(err=errno))
        return attr

    def post_recv(self, RecvWR wr not None, RecvWR bad_wr=None):
        cdef v.ibv_recv_wr *my_bad_wr
        rc = v.ibv_post_srq_recv(self.srq, &wr.recv_wr, &my_bad_wr)
        if rc != 0:
            if bad_wr:
                memcpy(&bad_wr.recv_wr, my_bad_wr, sizeof(bad_wr.recv_wr))
            raise PyverbsRDMAErrno('Failed to post receive to SRQ ({err})'.
                              format(err=rc))
