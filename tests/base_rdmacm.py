# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc . All rights reserved. See COPYING file

import abc

from pyverbs.cmid import CMID, AddrInfo, CMEventChannel, ConnParam, UDParam
from pyverbs.qp import QPCap, QPInitAttr, QPAttr, QP
from pyverbs.pyverbs_error import PyverbsUserError
import pyverbs.cm_enums as ce
import pyverbs.enums as e
from pyverbs.cq import CQ


GRH_SIZE = 40
qp_type_per_ps = {ce.RDMA_PS_TCP: e.IBV_QPT_RC, ce.RDMA_PS_UDP: e.IBV_QPT_UD}


class CMResources(abc.ABC):
    """
    CMResources class is an abstract base class which contains basic resources
    for RDMA CM communication.
    """
    def __init__(self, addr=None, passive=None, **kwargs):
        """
        :param addr: Local address to bind to.
        :param passive: Indicate if this CM is the passive CM.
        :param kwargs: Arguments:
            * *port* (str)
                Port number of the address
            * *with_ext_qp* (bool)
                If set, an external RC QP will be created and used by RDMACM
            * *port_space* (str)
                If set, indicates the CMIDs port space
        """
        self.qp_init_attr = None
        self.passive = passive
        self.with_ext_qp = kwargs.get('with_ext_qp', False)
        self.port = kwargs.get('port') if kwargs.get('port') else '7471'
        self.port_space = kwargs.get('port_space', ce.RDMA_PS_TCP)
        self.remote_operation = kwargs.get('remote_op')
        self.qp_type = qp_type_per_ps[self.port_space]
        self.qp_init_attr = QPInitAttr(qp_type=self.qp_type, cap=QPCap())
        self.connected = False
        # When passive side (server) listens to incoming connection requests,
        # for each new request it creates a new cmid which is used to establish
        # the connection with the remote side
        self.msg_size = 1024
        self.num_msgs = 10
        self.channel = None
        self.cq = None
        self.qps = {}
        self.mr = None
        self.remote_qpn = None
        self.ud_params = None
        self.child_ids = {}
        self.cmids = {}
        if self.passive:
            self.ai = AddrInfo(src=addr, src_service=self.port,
                               port_space=self.port_space, flags=ce.RAI_PASSIVE)
        else:
            self.ai = AddrInfo(src=addr, dst=addr, dst_service=self.port,
                               port_space=self.port_space)

    @property
    def child_id(self):
        if self.child_ids:
            return self.child_ids[0]

    @property
    def cmid(self):
        if self.cmids:
            return self.cmids[0]

    @property
    def qp(self):
        if self.qps:
            return self.qps[0]

    def create_mr(self):
        cmid = self.child_id if self.passive else self.cmid
        mr_remote_function = {None: cmid.reg_msgs, 'read': cmid.reg_read,
                              'write': cmid.reg_write}
        self.mr = mr_remote_function[self.remote_operation](self.msg_size + GRH_SIZE)

    def create_event_channel(self):
        self.channel = CMEventChannel()

    def create_qp_init_attr(self, rcq=None, scq=None):
        return QPInitAttr(qp_type=self.qp_type, rcq=rcq, scq=scq,
                          cap=QPCap(max_recv_wr=1))

    def create_conn_param(self, qp_num=0, conn_idx=0):
        if self.with_ext_qp:
            qp_num = self.qp.qp_num
        return ConnParam(qp_num=qp_num)

    def set_ud_params(self, cm_event):
        if self.port_space == ce.RDMA_PS_UDP:
            self.ud_params = UDParam(cm_event)

    def my_qp_number(self):
        if self.with_ext_qp:
            return self.qp.qp_num
        else:
            cm = self.child_id if self.passive else self.cmid
            return cm.qpn

    def create_qp(self, conn_idx=0):
        """
        Create an rdmacm QP. If self.with_ext_qp is set, then an external CQ and
        QP will be created. In case that CQ is already created, it is used
        for the newly created QP.
        :param conn_idx: The connection index.
        """
        cmid = self.child_id if self.passive else self.cmid
        if not self.with_ext_qp:
            cmid.create_qp(self.create_qp_init_attr())
        else:
            self.create_cq(cmid)
            init_attr = self.create_qp_init_attr(rcq=self.cq, scq=self.cq)
            self.qps[conn_idx] = QP(cmid.pd, init_attr, QPAttr())

    def create_cq(self, cmid):
        if not self.cq:
            self.cq = CQ(cmid.context, self.num_msgs, None, None, 0)

    def modify_ext_qp_to_rts(self, conn_idx=0):
        cmid = self.child_id if self.passive else self.cmid
        attr, mask = cmid.init_qp_attr(e.IBV_QPS_INIT)
        self.qps[conn_idx].modify(attr, mask)
        attr, mask = cmid.init_qp_attr(e.IBV_QPS_RTR)
        self.qps[conn_idx].modify(attr, mask)
        attr, mask = cmid.init_qp_attr(e.IBV_QPS_RTS)
        self.qps[conn_idx].modify(attr, mask)

    @abc.abstractmethod
    def create_child_id(self, cm_event=None):
        pass

    @property
    def mr_lkey(self):
        return self.mr.lkey


class AsyncCMResources(CMResources):
    """
    AsyncCMResources class contains resources for RDMA CM asynchronous
    communication.
    :param addr: Local address to bind to.
    :param passive: Indicate if this CM is the passive CM.
    """
    def __init__(self, addr=None, passive=None, **kwargs):
        super(AsyncCMResources, self).__init__(addr=addr, passive=passive,
                                               **kwargs)
        self.create_event_channel()

    def create_cmid(self, idx=0):
        self.cmids[idx] = CMID(creator=self.channel, port_space=self.port_space)

    def create_child_id(self, cm_event=None):
        if not self.passive:
            raise PyverbsUserError('create_child_id can be used only in passive side')
        new_child_idx = len(self.child_ids)
        self.child_ids[new_child_idx] = CMID(creator=cm_event, listen_id=self.cmid)


class SyncCMResources(CMResources):
    """
    SyncCMResources class contains resources for RDMA CM synchronous
    communication.
    :param addr: Local address to bind to.
    :param passive: Indicate if this CM is the passive CM.
    """
    def __init__(self, addr=None, passive=None, **kwargs):
        super(SyncCMResources, self).__init__(addr=addr, passive=passive,
                                              **kwargs)

    def create_cmid(self, idx=0):
        self.cmids[idx] = CMID(creator=self.ai, qp_init_attr=self.qp_init_attr)

    def create_child_id(self, cm_event=None):
        if not self.passive:
            raise PyverbsUserError('create_child_id can be used only in passive side')
        new_child_idx = len(self.child_ids)
        self.child_ids[new_child_idx] = self.cmid.get_request()
