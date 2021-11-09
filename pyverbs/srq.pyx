import weakref
from libc.errno cimport errno
from libc.string cimport memcpy
from libc.stdlib cimport malloc, free
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.wr cimport RecvWR, SGE, copy_sg_array
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
cimport pyverbs.libibverbs_enums as e
from pyverbs.device cimport Context
from pyverbs.cq cimport CQEX, CQ
cimport pyverbs.libibverbs as v
from pyverbs.xrcd cimport XRCD
from pyverbs.qp cimport QP
from pyverbs.pd cimport PD

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
    def max_num_tags(self):
        return self.attr.tm_cap.max_num_tags
    @max_num_tags.setter
    def max_num_tags(self, val):
        self.attr.tm_cap.max_num_tags = val

    @property
    def max_ops(self):
        return self.attr.tm_cap.max_ops
    @max_ops.setter
    def max_ops(self, val):
        self.attr.tm_cap.max_ops = val

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


cdef class OpsWr(PyverbsCM):
    def __init__(self, wr_id=0, opcode=e.IBV_WR_TAG_ADD, flags=e.IBV_OPS_SIGNALED,
                 OpsWr next_wr=None, unexpected_cnt=0, recv_wr_id=0,
                 num_sge=None, tag=0, mask=0, sg_list=None):
        self.ops_wr.wr_id = wr_id
        self.ops_wr.opcode = opcode
        self.ops_wr.flags = flags
        self.ops_wr.tm.unexpected_cnt = unexpected_cnt
        self.ops_wr.tm.add.recv_wr_id = recv_wr_id
        self.ops_wr.tm.add.tag = tag
        self.ops_wr.tm.add.mask = mask
        if next_wr is not None:
            self.ops_wr.next = &next_wr.ops_wr
        if num_sge is not None:
            self.ops_wr.tm.add.num_sge = num_sge
        cdef v.ibv_sge *dst
        if sg_list is not None:
            self.ops_wr.tm.add.sg_list = <v.ibv_sge*>malloc(num_sge * sizeof(v.ibv_sge))
            if self.ops_wr.tm.add.sg_list == NULL:
                raise MemoryError('Failed to malloc SG buffer')
            dst = self.ops_wr.tm.add.sg_list
            copy_sg_array(dst, sg_list, num_sge)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.ops_wr.tm.add.sg_list != NULL:
            free(self.ops_wr.tm.add.sg_list)
            self.ops_wr.tm.add.sg_list = NULL

    @property
    def wr_id(self):
        return self.ops_wr.wr_id
    @wr_id.setter
    def wr_id(self, val):
        self.ops_wr.wr_id = val

    @property
    def next_wr(self):
        if self.ops_wr.next == NULL:
            return None
        val = OpsWr()
        val.ops_wr = self.ops_wr.next[0]
        return val
    @next_wr.setter
    def next_wr(self, OpsWr val not None):
        self.ops_wr.next = &val.ops_wr

    @property
    def opcode(self):
        return self.ops_wr.opcode
    @opcode.setter
    def opcode(self, val):
        self.ops_wr.opcode = val

    @property
    def flags(self):
        return self.ops_wr.flags
    @flags.setter
    def flags(self, val):
        self.ops_wr.flags = val

    @property
    def unexpected_cnt(self):
        return self.ops_wr.tm.unexpected_cnt
    @unexpected_cnt.setter
    def unexpected_cnt(self, val):
        self.ops_wr.tm.unexpected_cnt = val

    @property
    def recv_wr_id(self):
        return self.ops_wr.tm.add.recv_wr_id
    @recv_wr_id.setter
    def recv_wr_id(self, val):
        self.ops_wr.tm.add.recv_wr_id = val

    @property
    def tag(self):
        return self.ops_wr.tm.add.tag
    @tag.setter
    def tag(self, val):
        self.ops_wr.tm.add.tag = val

    @property
    def handle(self):
        return self.ops_wr.tm.handle
    @handle.setter
    def handle(self, val):
        self.ops_wr.tm.handle = val

    @property
    def mask(self):
        return self.ops_wr.tm.add.mask
    @mask.setter
    def mask(self, val):
        self.ops_wr.tm.add.mask = val


cdef class SRQ(PyverbsCM):
    def __init__(self, object creator not None, object attr not None):
        super().__init__()
        self.srq = NULL
        self.cq = None
        self.qps = weakref.WeakSet()
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
        if self.srq != NULL:
            if self.logger:
                self.logger.debug('Closing SRQ')
            close_weakrefs([self.qps])
            rc = v.ibv_destroy_srq(self.srq)
            if rc != 0:
                raise PyverbsRDMAError('Failed to destroy SRQ', rc)
            self.srq = NULL
            self.cq =None

    cdef add_ref(self, obj):
        if isinstance(obj, QP):
            self.qps.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    def _create_srq(self, PD pd, SrqInitAttr init_attr):
        self.srq = v.ibv_create_srq(pd.pd, &init_attr.attr)
        pd.add_ref(self)

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
           raise PyverbsRDMAError('Failed to retrieve SRQ number', rc)
        return srqn

    def modify(self, SrqAttr attr, comp_mask):
        rc = v.ibv_modify_srq(self.srq, &attr.attr, comp_mask)
        if rc != 0:
            raise PyverbsRDMAError('Failed to modify SRQ', rc)

    def query(self):
        attr = SrqAttr()
        rc = v.ibv_query_srq(self.srq, &attr.attr)
        if rc != 0:
            raise PyverbsRDMAError('Failed to query SRQ', rc)
        return attr

    def post_srq_ops(self, OpsWr wr not None, OpsWr bad_wr=None):
        """
        Perform on a special shared receive queue (SRQ) configuration manipulations
        :param wr: Ops Work Requests to be posted to the TM-Shared Receive Queue
        :param bad_wr: A pointer that will be filled with the first Ops Work Request,
                       that its processing failed
        """
        cdef v.ibv_ops_wr *my_bad_wr
        rc= v.ibv_post_srq_ops(self.srq, &wr.ops_wr, &my_bad_wr)
        if rc != 0:
            if bad_wr:
                memcpy(&bad_wr.ops_wr, my_bad_wr, sizeof(bad_wr.ops_wr))
            raise PyverbsRDMAError('post SRQ ops failed.', rc)

    def post_recv(self, RecvWR wr not None, RecvWR bad_wr=None):
        cdef v.ibv_recv_wr *my_bad_wr
        rc = v.ibv_post_srq_recv(self.srq, &wr.recv_wr, &my_bad_wr)
        if rc != 0:
            if bad_wr:
                memcpy(&bad_wr.recv_wr, my_bad_wr, sizeof(bad_wr.recv_wr))
            raise PyverbsRDMAError('Failed to post receive to SRQ.', rc)
