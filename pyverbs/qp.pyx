# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved.
from pyverbs.utils import gid_str, qp_type_to_str, qp_state_to_str, mtu_to_str
from pyverbs.utils import access_flags_to_str, mig_state_to_str
from pyverbs.pyverbs_error import PyverbsUserError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.wr cimport RecvWR, SendWR
cimport pyverbs.libibverbs_enums as e
from pyverbs.addr cimport AHAttr, GID
from pyverbs.addr cimport GlobalRoute
from pyverbs.device cimport Context
from pyverbs.cq cimport CQ, CQEX
cimport pyverbs.libibverbs as v
from pyverbs.xrcd cimport XRCD
from pyverbs.srq cimport SRQ
from pyverbs.pd cimport PD
from libc.string cimport memcpy


cdef class QPCap(PyverbsObject):
    def __init__(self, max_send_wr=1, max_recv_wr=10, max_send_sge=1,
                 max_recv_sge=1, max_inline_data=0):
        """
        Initializes a QPCap object with user-provided or default values.
        :param max_send_wr: max number of outstanding WRs in the SQ
        :param max_recv_wr: max number of outstanding WRs in the RQ
        :param max_send_sge: Requested max number of scatter-gather elements in
                             a WR in the SQ
        :param max_recv_sge: Requested max number of scatter-gather elements in
                             a WR in the RQ
        :param max_inline_data: max number of data (bytes) that can be posted
                                inline to the SQ, otherwise 0
        :return:
        """
        super().__init__()
        self.cap.max_send_wr = max_send_wr
        self.cap.max_recv_wr = max_recv_wr
        self.cap.max_send_sge = max_send_sge
        self.cap.max_recv_sge = max_recv_sge
        self.cap.max_inline_data = max_inline_data

    @property
    def max_send_wr(self):
        return self.cap.max_send_wr
    @max_send_wr.setter
    def max_send_wr(self, val):
        self.cap.max_send_wr = val

    @property
    def max_recv_wr(self):
        return self.cap.max_recv_wr
    @max_recv_wr.setter
    def max_recv_wr(self, val):
        self.cap.max_recv_wr = val

    @property
    def max_send_sge(self):
        return self.cap.max_send_sge
    @max_send_sge.setter
    def max_send_sge(self, val):
        self.cap.max_send_sge = val

    @property
    def max_recv_sge(self):
        return self.cap.max_recv_sge
    @max_recv_sge.setter
    def max_recv_sge(self, val):
        self.cap.max_recv_sge = val

    @property
    def max_inline_data(self):
        return self.cap.max_inline_data
    @max_inline_data.setter
    def max_inline_data(self, val):
        self.cap.max_inline_data = val

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('max send wrs', self.cap.max_send_wr) +\
               print_format.format('max recv wrs', self.cap.max_recv_wr) +\
               print_format.format('max send sges', self.cap.max_send_sge) +\
               print_format.format('max recv sges', self.cap.max_recv_sge) +\
               print_format.format('max inline data', self.cap.max_inline_data)


cdef class QPInitAttr(PyverbsObject):
    def __init__(self, qp_type=e.IBV_QPT_UD, qp_context=None,
                 PyverbsObject scq=None, PyverbsObject rcq=None,
                 SRQ srq=None, QPCap cap=None, sq_sig_all=1):
        """
        Initializes a QpInitAttr object representing ibv_qp_init_attr struct.
        Note that SRQ object is not yet supported in pyverbs so can't be passed
        as a parameter. None should be used until such support is added.
        :param qp_type: The desired QP type (see enum ibv_qp_type)
        :param qp_context: Associated QP context
        :param scq: Send CQ to be used for this QP
        :param rcq: Receive CQ to be used for this QP
        :param srq: Shared receive queue to be used as RQ in QP
        :param cap: A QPCap object
        :param sq_sig_all: If set, each send WR will generate a completion
                           entry
        :return: A QpInitAttr object
        """
        super().__init__()
        _copy_caps(cap, self)
        self.attr.qp_context = <void*>qp_context
        if scq is not None:
            if type(scq) is CQ:
                self.attr.send_cq = (<CQ>scq).cq
            elif type(scq) is CQEX:
                self.attr.send_cq = (<CQEX>scq).ibv_cq
            else:
                raise PyverbsUserError('Expected CQ/CQEX, got {t}'.\
                                       format(t=type(scq)))
        self.scq = scq

        if rcq is not None:
            if type(rcq) is CQ:
                self.attr.recv_cq = (<CQ>rcq).cq
            elif type(rcq) is CQEX:
                self.attr.recv_cq = (<CQEX>rcq).ibv_cq
            else:
                raise PyverbsUserError('Expected CQ/CQEX, got {t}'.\
                                       format(t=type(rcq)))
        self.rcq = rcq
        self.attr.qp_type = qp_type
        self.attr.sq_sig_all = sq_sig_all
        self.srq = srq
        self.attr.srq = srq.srq if srq else NULL

    @property
    def send_cq(self):
        return self.scq
    @send_cq.setter
    def send_cq(self, val):
        if type(val) is CQ:
            self.attr.send_cq = (<CQ>val).cq
        elif type(val) is CQEX:
            self.attr.send_cq = (<CQEX>val).ibv_cq
        self.scq = val

    @property
    def srq(self):
        return self.srq
    @srq.setter
    def srq(self, SRQ val):
        self.attr.srq = <v.ibv_srq*>val.srq
        self.srq = val

    @property
    def recv_cq(self):
        return self.rcq
    @recv_cq.setter
    def recv_cq(self, val):
        if type(val) is CQ:
            self.attr.recv_cq = (<CQ>val).cq
        elif type(val) is CQEX:
            self.attr.recv_cq = (<CQEX>val).ibv_cq
        self.rcq = val

    @property
    def cap(self):
        return QPCap(max_send_wr=self.attr.cap.max_send_wr,
                     max_recv_wr=self.attr.cap.max_recv_wr,
                     max_send_sge=self.attr.cap.max_send_sge,
                     max_recv_sge=self.attr.cap.max_recv_sge,
                     max_inline_data=self.attr.cap.max_inline_data)
    @cap.setter
    def cap(self, val):
        _copy_caps(val, self)

    @property
    def qp_type(self):
        return self.attr.qp_type
    @qp_type.setter
    def qp_type(self, val):
        self.attr.qp_type = val

    @property
    def sq_sig_all(self):
        return self.attr.sq_sig_all
    @sq_sig_all.setter
    def sq_sig_all(self, val):
        self.attr.sq_sig_all = val

    @property
    def max_send_wr(self):
        return self.attr.cap.max_send_wr
    @max_send_wr.setter
    def max_send_wr(self, val):
        self.attr.cap.max_send_wr = val

    @property
    def max_recv_wr(self):
        return self.attr.cap.max_recv_wr
    @max_recv_wr.setter
    def max_recv_wr(self, val):
        self.attr.cap.max_recv_wr = val

    @property
    def max_send_sge(self):
        return self.attr.cap.max_send_sge
    @max_send_sge.setter
    def max_send_sge(self, val):
        self.attr.cap.max_send_sge = val

    @property
    def max_recv_sge(self):
        return self.attr.cap.max_recv_sge
    @max_recv_sge.setter
    def max_recv_sge(self, val):
        self.attr.cap.max_recv_sge = val

    @property
    def max_inline_data(self):
        return self.attr.cap.max_inline_data
    @max_inline_data.setter
    def max_inline_data(self, val):
        self.attr.cap.max_inline_data = val

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        ident_format = '    {:20}: {:<20}\n'
        return print_format.format('QP type', qp_type_to_str(self.qp_type)) +\
               print_format.format('SQ sig. all', self.sq_sig_all) +\
               'QP caps:\n' +\
               ident_format.format('max send WR', self.attr.cap.max_send_wr) +\
               ident_format.format('max recv WR', self.attr.cap.max_recv_wr) +\
               ident_format.format('max send SGE',
                                   self.attr.cap.max_send_sge) +\
               ident_format.format('max recv SGE',
                                   self.attr.cap.max_recv_sge) +\
               ident_format.format('max inline data',
                                   self.attr.cap.max_inline_data)


cdef class QPInitAttrEx(PyverbsObject):
    def __init__(self, qp_type=e.IBV_QPT_UD, qp_context=None,
                 PyverbsObject scq=None, PyverbsObject rcq=None,
                 SRQ srq=None, QPCap cap=None, sq_sig_all=0, comp_mask=0,
                 PD pd=None, XRCD xrcd=None, create_flags=0,
                 max_tso_header=0, source_qpn=0, object hash_conf=None,
                 object ind_table=None):
        """
        Initialize a QPInitAttrEx object with user-defined or default values.
        :param qp_type: QP type to be created
        :param qp_context: Associated user context
        :param scq: Send CQ to be used for this QP
        :param rcq: Recv CQ to be used for this QP
        :param srq: Shared receive queue to be used as RQ in QP
        :param cap: A QPCap object
        :param sq_sig_all: If set, each send WR will generate a completion
                           entry
        :param comp_mask: bit mask to determine which of the following fields
                          are valid
        :param pd: A PD object to be associated with this QP
        :param xrcd: XRC domain to be used for XRC QPs
        :param create_flags: Creation flags for this QP
        :param max_tso_header: Maximum TSO header size
        :param source_qpn: Source QP number (requires IBV_QP_CREATE_SOURCE_QPN
                           set in create_flags)
        :param hash_conf: Not yet supported
        :param ind_table: Not yet supported
        :return: An initialized QPInitAttrEx object
        """
        super().__init__()
        _copy_caps(cap, self)
        if scq is not None:
            if type(scq) is CQ:
                self.attr.send_cq = (<CQ>scq).cq
            elif type(scq) is CQEX:
                self.attr.send_cq = (<CQEX>scq).ibv_cq
            else:
                raise PyverbsUserError('Expected CQ/CQEX, got {t}'.\
                                       format(t=type(scq)))
        self.scq = scq

        if rcq is not None:
            if type(rcq) is CQ:
                self.attr.recv_cq = (<CQ>rcq).cq
            elif type(rcq) is CQEX:
                self.attr.recv_cq = (<CQEX>rcq).ibv_cq
            else:
                raise PyverbsUserError('Expected CQ/CQEX, got {t}'.\
                                       format(t=type(rcq)))
        self.rcq = rcq

        self.srq = srq
        self.attr.srq = srq.srq if srq else NULL
        self.xrcd = xrcd
        self.attr.xrcd = xrcd.xrcd if xrcd else NULL
        self.attr.rwq_ind_tbl = NULL  # Until RSS support is added
        self.attr.qp_type = qp_type
        self.attr.sq_sig_all = sq_sig_all
        unsupp_flags = e.IBV_QP_INIT_ATTR_IND_TABLE | e.IBV_QP_INIT_ATTR_RX_HASH
        if comp_mask & unsupp_flags:
            raise PyverbsUserError('RSS is not yet supported in pyverbs')
        self.attr.comp_mask = comp_mask
        if pd is not None:
            self._pd = pd
            self.attr.pd = pd.pd
        self.attr.create_flags = create_flags
        self.attr.max_tso_header = max_tso_header
        self.attr.source_qpn = source_qpn

    @property
    def send_cq(self):
        return self.scq
    @send_cq.setter
    def send_cq(self, val):
        if type(val) is CQ:
            self.attr.send_cq = (<CQ>val).cq
        elif type(val) is CQEX:
            self.attr.send_cq = (<CQEX>val).ibv_cq
        self.scq = val

    @property
    def recv_cq(self):
        return self.rcq
    @recv_cq.setter
    def recv_cq(self, val):
        if type(val) is CQ:
            self.attr.recv_cq = (<CQ>val).cq
        elif type(val) is CQEX:
            self.attr.recv_cq = (<CQEX>val).ibv_cq
        self.rcq = val

    @property
    def cap(self):
        return QPCap(max_send_wr=self.attr.cap.max_send_wr,
                     max_recv_wr=self.attr.cap.max_recv_wr,
                     max_send_sge=self.attr.cap.max_send_sge,
                     max_recv_sge=self.attr.cap.max_recv_sge,
                     max_inline_data=self.attr.cap.max_inline_data)
    @cap.setter
    def cap(self, val):
        _copy_caps(val, self)

    @property
    def qp_type(self):
        return self.attr.qp_type
    @qp_type.setter
    def qp_type(self, val):
        self.attr.qp_type = val

    @property
    def sq_sig_all(self):
        return self.attr.sq_sig_all
    @sq_sig_all.setter
    def sq_sig_all(self, val):
        self.attr.sq_sig_all = val

    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val

    @property
    def pd(self):
        return self._pd
    @pd.setter
    def pd(self, PD val):
        self.attr.pd = <v.ibv_pd*>val.pd
        self._pd = val

    @property
    def xrcd(self):
        return self.xrcd
    @xrcd.setter
    def xrcd(self, XRCD val):
        self.attr.xrcd = <v.ibv_xrcd*>val.xrcd
        self.xrcd = val

    @property
    def srq(self):
        return self.srq
    @srq.setter
    def srq(self, SRQ val):
        self.attr.srq = <v.ibv_srq*>val.srq
        self.srq = val

    @property
    def create_flags(self):
        return self.attr.create_flags
    @create_flags.setter
    def create_flags(self, val):
        self.attr.create_flags = val

    @property
    def max_tso_header(self):
        return self.attr.max_tso_header
    @max_tso_header.setter
    def max_tso_header(self, val):
        self.attr.max_tso_header = val

    @property
    def source_qpn(self):
        return self.attr.source_qpn
    @source_qpn.setter
    def source_qpn(self, val):
        self.attr.source_qpn = val

    @property
    def max_send_wr(self):
        return self.attr.cap.max_send_wr
    @max_send_wr.setter
    def max_send_wr(self, val):
        self.attr.cap.max_send_wr = val

    @property
    def max_recv_wr(self):
        return self.attr.cap.max_recv_wr
    @max_recv_wr.setter
    def max_recv_wr(self, val):
        self.attr.cap.max_recv_wr = val

    @property
    def max_send_sge(self):
        return self.attr.cap.max_send_sge
    @max_send_sge.setter
    def max_send_sge(self, val):
        self.attr.cap.max_send_sge = val

    @property
    def max_recv_sge(self):
        return self.attr.cap.max_recv_sge
    @max_recv_sge.setter
    def max_recv_sge(self, val):
        self.attr.cap.max_recv_sge = val

    @property
    def max_inline_data(self):
        return self.attr.cap.max_inline_data
    @max_inline_data.setter
    def max_inline_data(self, val):
        self.attr.cap.max_inline_data = val

    def mask_to_str(self, mask):
        comp_masks = {1: 'PD', 2: 'XRCD', 4: 'Create Flags',
                      8: 'Max TSO header', 16: 'Indirection Table',
                      32: 'RX hash'}
        mask_str = ''
        for f in comp_masks:
            if mask & f:
                mask_str += comp_masks[f]
                mask_str += ' '
        return mask_str

    def flags_to_str(self, flags):
        create_flags = {1: 'Block self mcast loopback', 2: 'Scatter FCS',
                        4: 'CVLAN stripping', 8: 'Source QPN',
                        16: 'PCI write end padding'}
        create_str = ''
        for f in create_flags:
            if flags & f:
                create_str += create_flags[f]
                create_str += ' '
        return create_str

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('QP type', qp_type_to_str(self.qp_type)) +\
               print_format.format('SQ sig. all', self.sq_sig_all) +\
               'QP caps:\n' +\
               print_format.format('  max send WR',
                                   self.attr.cap.max_send_wr) +\
               print_format.format('  max recv WR',
                                   self.attr.cap.max_recv_wr) +\
               print_format.format('  max send SGE',
                                   self.attr.cap.max_send_sge) +\
               print_format.format('  max recv SGE',
                                   self.attr.cap.max_recv_sge) +\
               print_format.format('  max inline data',
                                   self.attr.cap.max_inline_data) +\
               print_format.format('comp mask',
                                   self.mask_to_str(self.attr.comp_mask)) +\
               print_format.format('create flags',
                                   self.flags_to_str(self.attr.create_flags)) +\
               print_format.format('max TSO header',
                                   self.attr.max_tso_header) +\
               print_format.format('Source QPN', self.attr.source_qpn)


cdef class QPAttr(PyverbsObject):
    def __init__(self, qp_state=e.IBV_QPS_INIT, cur_qp_state=e.IBV_QPS_RESET,
                 port_num=1, path_mtu=e.IBV_MTU_1024):
        """
        Initializes a QPQttr object which represents ibv_qp_attr structs. It
        can be used to modify a QP.
        This function initializes default values for reset-to-init transition.
        :param qp_state: Desired QP state
        :param cur_qp_state: Current QP state
        :return: An initialized QpAttr object
        """
        super().__init__()
        self.attr.qp_state = qp_state
        self.attr.cur_qp_state = cur_qp_state
        self.attr.port_num = port_num
        self.attr.path_mtu = path_mtu

    @property
    def qp_state(self):
        return self.attr.qp_state
    @qp_state.setter
    def qp_state(self, val):
        self.attr.qp_state = val

    @property
    def cur_qp_state(self):
        return self.attr.cur_qp_state
    @cur_qp_state.setter
    def cur_qp_state(self, val):
        self.attr.cur_qp_state = val

    @property
    def path_mtu(self):
        return self.attr.path_mtu
    @path_mtu.setter
    def path_mtu(self, val):
        self.attr.path_mtu = val

    @property
    def path_mig_state(self):
        return self.attr.path_mig_state
    @path_mig_state.setter
    def path_mig_state(self, val):
        self.attr.path_mig_state = val

    @property
    def qkey(self):
        return self.attr.qkey
    @qkey.setter
    def qkey(self, val):
        self.attr.qkey = val

    @property
    def rq_psn(self):
        return self.attr.rq_psn
    @rq_psn.setter
    def rq_psn(self, val):
        self.attr.rq_psn = val

    @property
    def sq_psn(self):
        return self.attr.sq_psn
    @sq_psn.setter
    def sq_psn(self, val):
        self.attr.sq_psn = val

    @property
    def dest_qp_num(self):
        return self.attr.dest_qp_num
    @dest_qp_num.setter
    def dest_qp_num(self, val):
        self.attr.dest_qp_num = val

    @property
    def qp_access_flags(self):
        return self.attr.qp_access_flags
    @qp_access_flags.setter
    def qp_access_flags(self, val):
        self.attr.qp_access_flags = val

    @property
    def cap(self):
        return QPCap(max_send_wr=self.attr.cap.max_send_wr,
                     max_recv_wr=self.attr.cap.max_recv_wr,
                     max_send_sge=self.attr.cap.max_send_sge,
                     max_recv_sge=self.attr.cap.max_recv_sge,
                     max_inline_data=self.attr.cap.max_inline_data)
    @cap.setter
    def cap(self, val):
        _copy_caps(val, self)

    @property
    def ah_attr(self):
        if self.attr.ah_attr.is_global:
            gid = gid_str(self.attr.ah_attr.grh.dgid._global.subnet_prefix,
                          self.attr.ah_attr.grh.dgid._global.interface_id)
            g = GID(gid)
            gr = GlobalRoute(flow_label=self.attr.ah_attr.grh.flow_label,
                             sgid_index=self.attr.ah_attr.grh.sgid_index,
                             hop_limit=self.attr.ah_attr.grh.hop_limit, dgid=g,
                             traffic_class=self.attr.ah_attr.grh.traffic_class)
        else:
            gr = None
        ah = AHAttr(dlid=self.attr.ah_attr.dlid, sl=self.attr.ah_attr.sl,
                    port_num=self.attr.ah_attr.port_num,
                    src_path_bits=self.attr.ah_attr.src_path_bits,
                    static_rate=self.attr.ah_attr.static_rate,
                    is_global=self.attr.ah_attr.is_global, gr=gr)
        return ah

    @ah_attr.setter
    def ah_attr(self, val):
        self._copy_ah(val)

    @property
    def alt_ah_attr(self):
        if self.attr.alt_ah_attr.is_global:
            gid = gid_str(self.attr.alt_ah_attr.grh.dgid._global.subnet_prefix,
                          self.attr.alt_ah_attr.grh.dgid._global.interface_id)
            g = GID(gid)
            gr = GlobalRoute(flow_label=self.attr.alt_ah_attr.grh.flow_label,
                             sgid_index=self.attr.alt_ah_attr.grh.sgid_index,
                             hop_limit=self.attr.alt_ah_attr.grh.hop_limit,
                             dgid=g,
                             traffic_class=self.attr.alt_ah_attr.grh.traffic_class)
        else:
            gr = None
        ah = AHAttr(dlid=self.attr.alt_ah_attr.dlid,
                    port_num=self.attr.ah_attr.port_num,
                    sl=self.attr.alt_ah_attr.sl,
                    src_path_bits=self.attr.alt_ah_attr.src_path_bits,
                    static_rate=self.attr.alt_ah_attr.static_rate,
                    is_global=self.attr.alt_ah_attr.is_global, gr=gr)
        return ah

    @alt_ah_attr.setter
    def alt_ah_attr(self, val):
        self._copy_ah(val, True)

    def _copy_ah(self, AHAttr ah_attr, is_alt=False):
        if ah_attr is None:
            return
        if not is_alt:
            for i in range(16):
                self.attr.ah_attr.grh.dgid.raw[i] = \
                    ah_attr.ah_attr.grh.dgid.raw[i]
            self.attr.ah_attr.grh.flow_label = ah_attr.ah_attr.grh.flow_label
            self.attr.ah_attr.grh.sgid_index = ah_attr.ah_attr.grh.sgid_index
            self.attr.ah_attr.grh.hop_limit = ah_attr.ah_attr.grh.hop_limit
            self.attr.ah_attr.grh.traffic_class = \
                ah_attr.ah_attr.grh.traffic_class
            self.attr.ah_attr.dlid = ah_attr.ah_attr.dlid
            self.attr.ah_attr.sl = ah_attr.ah_attr.sl
            self.attr.ah_attr.src_path_bits = ah_attr.ah_attr.src_path_bits
            self.attr.ah_attr.static_rate = ah_attr.ah_attr.static_rate
            self.attr.ah_attr.is_global = ah_attr.ah_attr.is_global
            self.attr.ah_attr.port_num = ah_attr.ah_attr.port_num
        else:
            for i in range(16):
                self.attr.alt_ah_attr.grh.dgid.raw[i] = \
                    ah_attr.ah_attr.grh.dgid.raw[i]
            self.attr.alt_ah_attr.grh.flow_label = \
                ah_attr.ah_attr.grh.flow_label
            self.attr.alt_ah_attr.grh.sgid_index = \
                ah_attr.ah_attr.grh.sgid_index
            self.attr.alt_ah_attr.grh.hop_limit = ah_attr.ah_attr.grh.hop_limit
            self.attr.alt_ah_attr.grh.traffic_class = \
                ah_attr.ah_attr.grh.traffic_class
            self.attr.alt_ah_attr.dlid = ah_attr.ah_attr.dlid
            self.attr.alt_ah_attr.sl = ah_attr.ah_attr.sl
            self.attr.alt_ah_attr.src_path_bits = ah_attr.ah_attr.src_path_bits
            self.attr.alt_ah_attr.static_rate = ah_attr.ah_attr.static_rate
            self.attr.alt_ah_attr.is_global = ah_attr.ah_attr.is_global
            self.attr.alt_ah_attr.port_num = ah_attr.ah_attr.port_num

    @property
    def pkey_index(self):
        return self.attr.pkey_index
    @pkey_index.setter
    def pkey_index(self, val):
        self.attr.pkey_index = val

    @property
    def alt_pkey_index(self):
        return self.attr.alt_pkey_index
    @alt_pkey_index.setter
    def alt_pkey_index(self, val):
        self.attr.alt_pkey_index = val

    @property
    def en_sqd_async_notify(self):
        return self.attr.en_sqd_async_notify
    @en_sqd_async_notify.setter
    def en_sqd_async_notify(self, val):
        self.attr.en_sqd_async_notify = val

    @property
    def sq_draining(self):
        return self.attr.sq_draining
    @sq_draining.setter
    def sq_draining(self, val):
        self.attr.sq_draining = val

    @property
    def max_rd_atomic(self):
        return self.attr.max_rd_atomic
    @max_rd_atomic.setter
    def max_rd_atomic(self, val):
        self.attr.max_rd_atomic = val

    @property
    def max_dest_rd_atomic(self):
        return self.attr.max_dest_rd_atomic
    @max_dest_rd_atomic.setter
    def max_dest_rd_atomic(self, val):
        self.attr.max_dest_rd_atomic = val

    @property
    def min_rnr_timer(self):
        return self.attr.min_rnr_timer
    @min_rnr_timer.setter
    def min_rnr_timer(self, val):
        self.attr.min_rnr_timer = val

    @property
    def port_num(self):
        return self.attr.port_num
    @port_num.setter
    def port_num(self, val):
        self.attr.port_num = val

    @property
    def timeout(self):
        return self.attr.timeout
    @timeout.setter
    def timeout(self, val):
        self.attr.timeout = val

    @property
    def retry_cnt(self):
        return self.attr.retry_cnt
    @retry_cnt.setter
    def retry_cnt(self, val):
        self.attr.retry_cnt = val

    @property
    def rnr_retry(self):
        return self.attr.rnr_retry
    @rnr_retry.setter
    def rnr_retry(self, val):
        self.attr.rnr_retry = val

    @property
    def alt_port_num(self):
        return self.attr.alt_port_num
    @alt_port_num.setter
    def alt_port_num(self, val):
        self.attr.alt_port_num = val

    @property
    def alt_timeout(self):
        return self.attr.alt_timeout
    @alt_timeout.setter
    def alt_timeout(self, val):
        self.attr.alt_timeout = val

    @property
    def rate_limit(self):
        return self.attr.rate_limit
    @rate_limit.setter
    def rate_limit(self, val):
        self.attr.rate_limit = val

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        ah_format = '    {:22}: {:<20}\n'
        ident_format = '  {:22}: {:<20}\n'
        if self.attr.ah_attr.is_global:
            global_ah = ah_format.format('dgid',
                                         gid_str(self.attr.ah_attr.grh.dgid._global.subnet_prefix,
                                                 self.attr.ah_attr.grh.dgid._global.interface_id)) +\
                        ah_format.format('flow label',
                                         self.attr.ah_attr.grh.flow_label) +\
                        ah_format.format('sgid index',
                                         self.attr.ah_attr.grh.sgid_index) +\
                        ah_format.format('hop limit',
                                         self.attr.ah_attr.grh.hop_limit) +\
                        ah_format.format('traffic_class',
                                         self.attr.ah_attr.grh.traffic_class)
        else:
            global_ah = ''
        if self.attr.alt_ah_attr.is_global:
            alt_global_ah = ah_format.format('dgid',
                                             gid_str(self.attr.alt_ah_attr.grh.dgid._global.subnet_prefix,
                                                     self.attr.alt_ah_attr.grh.dgid._global.interface_id)) +\
                            ah_format.format('flow label',
                                             self.attr.alt_ah_attr.grh.flow_label) +\
                            ah_format.format('sgid index',
                                             self.attr.alt_ah_attr.grh.sgid_index) +\
                            ah_format.format('hop limit',
                                             self.attr.alt_ah_attr.grh.hop_limit) +\
                            ah_format.format('traffic_class',
                                             self.attr.alt_ah_attr.grh.traffic_class)
        else:
            alt_global_ah = ''
        return print_format.format('QP state',
                                   qp_state_to_str(self.attr.qp_state)) +\
               print_format.format('QP current state',
                            qp_state_to_str(self.attr.cur_qp_state)) +\
               print_format.format('Path MTU',
                                   mtu_to_str(self.attr.path_mtu)) +\
               print_format.format('Path mig. state',
                            mig_state_to_str(self.attr.path_mig_state)) +\
               print_format.format('QKey', self.attr.qkey) +\
               print_format.format('RQ PSN', self.attr.rq_psn) +\
               print_format.format('SQ PSN', self.attr.sq_psn) +\
               print_format.format('Dest QP number', self.attr.dest_qp_num) +\
               print_format.format('QP access flags',
                                   access_flags_to_str(self.attr.qp_access_flags)) +\
               'QP caps:\n' +\
               ident_format.format('max send WR',
                                   self.attr.cap.max_send_wr) +\
               ident_format.format('max recv WR',
                                   self.attr.cap.max_recv_wr) +\
               ident_format.format('max send SGE',
                                   self.attr.cap.max_send_sge) +\
               ident_format.format('max recv SGE',
                                   self.attr.cap.max_recv_sge) +\
               ident_format.format('max inline data',
                                   self.attr.cap.max_inline_data) +\
               'AH Attr:\n' +\
               ident_format.format('port num', self.attr.ah_attr.port_num) +\
               ident_format.format('sl', self.attr.ah_attr.sl) +\
               ident_format.format('source path bits',
                                   self.attr.ah_attr.src_path_bits) +\
               ident_format.format('dlid', self.attr.ah_attr.dlid) +\
               ident_format.format('port num', self.attr.ah_attr.port_num) +\
               ident_format.format('static rate',
                                   self.attr.ah_attr.static_rate) +\
               ident_format.format('is global',
                                   self.attr.ah_attr.is_global) +\
               global_ah +\
               'Alt. AH Attr:\n' +\
               ident_format.format('port num', self.attr.alt_ah_attr.port_num) +\
               ident_format.format('sl', self.attr.alt_ah_attr.sl) +\
               ident_format.format('source path bits',
                                   self.attr.alt_ah_attr.src_path_bits) +\
               ident_format.format('dlid', self.attr.alt_ah_attr.dlid) +\
               ident_format.format('port num', self.attr.alt_ah_attr.port_num) +\
               ident_format.format('static rate',
                                   self.attr.alt_ah_attr.static_rate) +\
               ident_format.format('is global',
                                   self.attr.alt_ah_attr.is_global) +\
               alt_global_ah +\
               print_format.format('PKey index', self.attr.pkey_index) +\
               print_format.format('Alt. PKey index',
                                   self.attr.alt_pkey_index) +\
               print_format.format('En. SQD async notify',
                                   self.attr.en_sqd_async_notify) +\
               print_format.format('SQ draining', self.attr.sq_draining) +\
               print_format.format('Max RD atomic', self.attr.max_rd_atomic) +\
               print_format.format('Max dest. RD atomic',
                                   self.attr.max_dest_rd_atomic) +\
               print_format.format('Min RNR timer', self.attr.min_rnr_timer) +\
               print_format.format('Port number', self.attr.port_num) +\
               print_format.format('Timeout', self.attr.timeout) +\
               print_format.format('Retry counter', self.attr.retry_cnt) +\
               print_format.format('RNR retry', self.attr.rnr_retry) +\
               print_format.format('Alt. port number',
                                   self.attr.alt_port_num) +\
               print_format.format('Alt. timeout', self.attr.alt_timeout) +\
               print_format.format('Rate limit', self.attr.rate_limit)


cdef class QP(PyverbsCM):
    def __init__(self, object creator not None, object init_attr not None,
                 QPAttr qp_attr=None):
        """
        Initializes a QP object and performs state transitions according to
        user request.
        A C ibv_qp object will be created using the provided init_attr.
        If a qp_attr object is provided, pyverbs will consider this a hint to
        transit the QP's state as far as possible towards RTS:
        - In case of UD and Raw Packet QP types, if a qp_attr is provided the
          QP will be returned in RTS state.
        - In case of connected QPs (RC, UC), remote QPN is needed for INIT2RTR
          transition, so if a qp_attr is provided, the QP will be returned in
          INIT state.
        :param creator: The object creating the QP. Can be of type PD so
                        ibv_create_qp will be used or of type Context, so
                        ibv_create_qp_ex will be used.
        :param init_attr: QP initial attributes of type QPInitAttr (when
                          created using PD) or QPInitAttrEx (when created
                          using Context).
        :param qp_attr: Optional QPAttr object. Will be used for QP state
                        transitions after creation.
        :return: An initialized QP object
        """
        cdef PD pd
        cdef Context ctx
        super().__init__()
        self.update_cqs(init_attr)
        # QP initialization was not done by the provider, we should do it here
        if self.qp == NULL:
            # In order to use cdef'd methods, a proper casting must be done,
            # let's infer the type.
            if issubclass(type(creator), Context):
                self._create_qp_ex(creator, init_attr)
                if self.qp == NULL:
                    raise PyverbsRDMAErrno('Failed to create QP')
                ctx = <Context>creator
                self.context = ctx
                ctx.add_ref(self)
                if init_attr.pd is not None:
                    pd = <PD>init_attr.pd
                    pd.add_ref(self)
                    self.pd = pd
                if init_attr.xrcd is not None:
                    xrcd = <XRCD>init_attr.xrcd
                    xrcd.add_ref(self)
                    self.xrcd = xrcd

            else:
                self._create_qp(creator, init_attr)
                if self.qp == NULL:
                    raise PyverbsRDMAErrno('Failed to create QP')
                pd = <PD>creator
                self.pd = pd
                pd.add_ref(self)
                self.context = None

        if qp_attr is not None:
            funcs = {e.IBV_QPT_RC: self.to_init, e.IBV_QPT_UC: self.to_init,
                     e.IBV_QPT_UD: self.to_rts,
                     e.IBV_QPT_XRC_RECV: self.to_init,
                     e.IBV_QPT_XRC_SEND: self.to_init,
                     e.IBV_QPT_RAW_PACKET: self.to_rts}
            funcs[self.qp.qp_type](qp_attr)

    cdef update_cqs(self, init_attr):
        cdef CQ cq
        cdef CQEX cqex
        if init_attr.send_cq is not None:
            if type(init_attr.send_cq) == CQ:
                cq = <CQ>init_attr.send_cq
                cq.add_ref(self)
                self.scq = cq
            else:
                cqex = <CQEX>init_attr.send_cq
                cqex.add_ref(self)
                self.scq = cqex
        if init_attr.send_cq != init_attr.recv_cq and init_attr.recv_cq is not None:
            if type(init_attr.recv_cq) == CQ:
                cq = <CQ>init_attr.recv_cq
                cq.add_ref(self)
                self.rcq = cq
            else:
                cqex = <CQEX>init_attr.recv_cq
                cqex.add_ref(self)
                self.rcq = cqex

    def _create_qp(self, PD pd, QPInitAttr attr):
        self.qp = v.ibv_create_qp(pd.pd, &attr.attr)

    def _create_qp_ex(self, Context ctx, QPInitAttrEx attr):
        self.qp = v.ibv_create_qp_ex(ctx.context, &attr.attr)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        self.logger.debug('Closing QP')
        if self.qp != NULL:
            if v.ibv_destroy_qp(self.qp):
                raise PyverbsRDMAErrno('Failed to destroy QP')
            self.qp = NULL
            self.pd = None
            self.context = None
            self.scq = None
            self.rcq = None

    def _get_comp_mask(self, dst):
        masks = {e.IBV_QPT_RC: {'INIT': e.IBV_QP_PKEY_INDEX | e.IBV_QP_PORT |\
                                e.IBV_QP_ACCESS_FLAGS, 'RTR': e.IBV_QP_AV |\
                                e.IBV_QP_PATH_MTU | e.IBV_QP_DEST_QPN |\
                                e.IBV_QP_RQ_PSN |\
                                e.IBV_QP_MAX_DEST_RD_ATOMIC |\
                                e.IBV_QP_MIN_RNR_TIMER,
                                'RTS': e.IBV_QP_TIMEOUT |\
                                e.IBV_QP_RETRY_CNT | e.IBV_QP_RNR_RETRY |\
                                e.IBV_QP_SQ_PSN | e.IBV_QP_MAX_QP_RD_ATOMIC},
                e.IBV_QPT_UC: {'INIT': e.IBV_QP_PKEY_INDEX | e.IBV_QP_PORT |\
                               e.IBV_QP_ACCESS_FLAGS, 'RTR': e.IBV_QP_AV |\
                               e.IBV_QP_PATH_MTU | e.IBV_QP_DEST_QPN |\
                               e.IBV_QP_RQ_PSN, 'RTS': e.IBV_QP_SQ_PSN},
                e.IBV_QPT_UD: {'INIT': e.IBV_QP_PKEY_INDEX | e.IBV_QP_PORT |\
                               e.IBV_QP_QKEY, 'RTR': 0,
                               'RTS': e.IBV_QP_SQ_PSN},
                e.IBV_QPT_RAW_PACKET: {'INIT': e.IBV_QP_PORT, 'RTR': 0,
                                       'RTS': 0},
                e.IBV_QPT_XRC_RECV: {'INIT': e.IBV_QP_PKEY_INDEX |\
                                e.IBV_QP_PORT | e.IBV_QP_ACCESS_FLAGS,
                                'RTR': e.IBV_QP_AV | e.IBV_QP_PATH_MTU |\
                                e.IBV_QP_DEST_QPN | e.IBV_QP_RQ_PSN |   \
                                e.IBV_QP_MAX_DEST_RD_ATOMIC |\
                                e.IBV_QP_MIN_RNR_TIMER,
                                'RTS': e.IBV_QP_TIMEOUT | e.IBV_QP_SQ_PSN },
                e.IBV_QPT_XRC_SEND: {'INIT': e.IBV_QP_PKEY_INDEX |\
                                e.IBV_QP_PORT | e.IBV_QP_ACCESS_FLAGS,
                                'RTR': e.IBV_QP_AV | e.IBV_QP_PATH_MTU |\
                                e.IBV_QP_DEST_QPN | e.IBV_QP_RQ_PSN,
                                'RTS': e.IBV_QP_TIMEOUT |\
                                e.IBV_QP_RETRY_CNT | e.IBV_QP_RNR_RETRY |\
                                e.IBV_QP_SQ_PSN | e.IBV_QP_MAX_QP_RD_ATOMIC}}

        return masks[self.qp.qp_type][dst] | e.IBV_QP_STATE

    def to_init(self, QPAttr qp_attr):
        """
        Modify the current QP's state to INIT. If the current state doesn't
        support transition to INIT, an exception will be raised.
        The comp mask provided to the kernel includes the needed bits for 2INIT
        transition for this QP type.
        :param qp_attr: QPAttr object containing the needed attributes for
                        2INIT transition
        :return: None
        """
        mask = self._get_comp_mask('INIT')
        qp_attr.qp_state = e.IBV_QPS_INIT
        rc =  v.ibv_modify_qp(self.qp, &qp_attr.attr, mask)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to modify QP state to init (returned {rc})'.
                                   format(rc=rc))

    def to_rtr(self, QPAttr qp_attr):
        """
        Modify the current QP's state to RTR. It assumes that its current
        state is INIT or RESET, in which case it will attempt a transition to
        INIT prior to transition to RTR. As a result, if current state doesn't
        support transition to INIT, an exception will be raised.
        The comp mask provided to the kernel includes the needed bits for 2RTR
        transition for this QP type.
        :param qp_attr: QPAttr object containing the needed attributes for
                        2RTR transition.
        :return: None
        """
        if self.qp_state != e.IBV_QPS_INIT: #assume reset
            self.to_init(qp_attr)
        mask = self._get_comp_mask('RTR')
        qp_attr.qp_state = e.IBV_QPS_RTR
        rc = v.ibv_modify_qp(self.qp, &qp_attr.attr, mask)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to modify QP state to RTR (returned {rc})'.
                                   format(rc=rc))

    def to_rts(self, QPAttr qp_attr):
        """
        Modify the current QP's state to RTS. It assumes that its current
        state is either RTR, INIT or RESET. If current state is not RTR, to_rtr()
        will be called.
        The comp mask provided to the kernel includes the needed bits for 2RTS
        transition for this QP type.
        :param qp_attr: QPAttr object containing the needed attributes for
                        2RTS transition.
        :return: None
        """
        if self.qp_state != e.IBV_QPS_RTR: #assume reset/init
            self.to_rtr(qp_attr)
        mask = self._get_comp_mask('RTS')
        qp_attr.qp_state = e.IBV_QPS_RTS
        rc = v.ibv_modify_qp(self.qp, &qp_attr.attr, mask)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to modify QP state to RTS (returned {rc})'.
                                   format(rc=rc))

    def query(self, attr_mask):
        """
        Query the QP
        :param attr_mask: The minimum list of attributes to retrieve. Some
                          devices may return additional attributes as well
                          (see enum ibv_qp_attr_mask)
        :return: (QPAttr, QPInitAttr) tuple containing the QP requested
                 attributes
        """
        attr = QPAttr()
        init_attr = QPInitAttr()
        rc = v.ibv_query_qp(self.qp, &attr.attr, attr_mask, &init_attr.attr)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to query QP (returned {rc})'.
                                   format(rc=rc))
        return attr, init_attr

    def modify(self, QPAttr qp_attr not None, comp_mask):
        """
        Modify the QP
        :param qp_attr: A QPAttr object with updated values to be applied to
                        the QP
        :param comp_mask: A bitmask specifying which QP attributes should be
                          modified (see enum ibv_qp_attr_mask)
        :return: None
        """
        rc = v.ibv_modify_qp(self.qp, &qp_attr.attr, comp_mask)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to modify QP (returned {rc})'.
                                   format(rc=rc))

    def post_recv(self, RecvWR wr not None, RecvWR bad_wr=None):
        """
        Post a receive WR on the QP.
        :param wr: The work request to post
        :param bad_wr: A RecvWR object to hold the bad WR if it is available in
                       case of a failure
        :return: None
        """
        cdef v.ibv_recv_wr *my_bad_wr
        # In order to provide a pointer to a pointer, use a temporary cdef'ed
        # variable.
        rc = v.ibv_post_recv(self.qp, &wr.recv_wr, &my_bad_wr)
        if rc != 0:
            if (bad_wr):
                memcpy(&bad_wr.recv_wr, my_bad_wr, sizeof(bad_wr.recv_wr))
            raise PyverbsRDMAErrno('Failed to post recv (returned {rc})'.
                                   format(rc=rc))

    def post_send(self, SendWR wr not None, SendWR bad_wr=None):
        """
        Post a send WR on the QP.
        :param wr: The work request to post
        :param bad_wr: A SendWR object to hold the bad WR if it is available in
                       case of a failure
        :return: None
        """
        # In order to provide a pointer to a pointer, use a temporary cdef'ed
        # variable.
        cdef v.ibv_send_wr *my_bad_wr
        rc = v.ibv_post_send(self.qp, &wr.send_wr, &my_bad_wr)
        if rc != 0:
            if (bad_wr):
                memcpy(&bad_wr.send_wr, my_bad_wr, sizeof(bad_wr.send_wr))
            raise PyverbsRDMAErrno('Failed to post send (returned {rc})'.
                                   format(rc=rc))

    @property
    def qp_type(self):
        return self.qp.qp_type

    @property
    def qp_state(self):
        return self.qp.state

    @property
    def qp_num(self):
        return self.qp.qp_num

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        return print_format.format('QP type', qp_type_to_str(self.qp_type)) +\
               print_format.format('  number', self.qp_num) +\
               print_format.format('  state', qp_state_to_str(self.qp_state))


def _copy_caps(QPCap src, dst):
    """
    Copy the QPCaps values of src into the inner ibv_qp_cap struct of dst.
    Since both ibv_qp_init_attr and ibv_qp_attr have an inner ibv_qp_cap inner
    struct, they can both be used.
    :param src: A QPCap object
    :param dst: A QPInitAttr / QPInitAttrEx / QPAttr object
    :return: None
    """
    # we're assigning to C structs here, we must have type-specific objects in
    # order to do that. Instead of having this function smaller but in 3
    # classes, it appears here once.
    cdef QPInitAttr qia
    cdef QPInitAttrEx qiae
    cdef QPAttr qa
    if src is None:
        return
    if type(dst) == QPInitAttr:
        qia = <QPInitAttr>dst
        qia.attr.cap.max_send_wr = src.cap.max_send_wr
        qia.attr.cap.max_recv_wr = src.cap.max_recv_wr
        qia.attr.cap.max_send_sge = src.cap.max_send_sge
        qia.attr.cap.max_recv_sge = src.cap.max_recv_sge
        qia.attr.cap.max_inline_data = src.cap.max_inline_data
    elif type(dst) == QPInitAttrEx:
        qiae = <QPInitAttrEx>dst
        qiae.attr.cap.max_send_wr = src.cap.max_send_wr
        qiae.attr.cap.max_recv_wr = src.cap.max_recv_wr
        qiae.attr.cap.max_send_sge = src.cap.max_send_sge
        qiae.attr.cap.max_recv_sge = src.cap.max_recv_sge
        qiae.attr.cap.max_inline_data = src.cap.max_inline_data
    else:
        qa = <QPAttr>dst
        qa.attr.cap.max_send_wr = src.cap.max_send_wr
        qa.attr.cap.max_recv_wr = src.cap.max_recv_wr
        qa.attr.cap.max_send_sge = src.cap.max_send_sge
        qa.attr.cap.max_recv_sge = src.cap.max_recv_sge
        qa.attr.cap.max_inline_data = src.cap.max_inline_data
