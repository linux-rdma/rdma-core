# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

from libc.stdint cimport uintptr_t, uint8_t, uint16_t, uint32_t
from libc.stdlib cimport calloc, free, malloc
from libc.string cimport memcpy
from posix.mman cimport munmap
import logging

from pyverbs.pyverbs_error import PyverbsUserError, PyverbsRDMAError, PyverbsError
from pyverbs.providers.mlx5.mlx5dv_sched cimport Mlx5dvSchedLeaf
cimport pyverbs.providers.mlx5.mlx5dv_enums as dve
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.qp cimport QPInitAttrEx, QPEx
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
cimport pyverbs.libibverbs_enums as e
from pyverbs.cq cimport CqInitAttrEx
cimport pyverbs.libibverbs as v
from pyverbs.device cimport DM
from pyverbs.addr cimport AH
from pyverbs.pd cimport PD


cdef char* _prepare_devx_inbox(in_bytes):
    """
    Auxiliary function that allocates inboxes for DevX commands, and fills them
    the bytes input.
    The allocated box must be freed when it's no longer needed.
    :param in_bytes: Stream of bytes of the command's input
    :return: The C allocated inbox
    """
    cdef char *in_bytes_c = in_bytes
    cdef char* in_mailbox = <char*>calloc(1, len(in_bytes))
    if in_mailbox == NULL:
        raise MemoryError('Failed to allocate memory')
    memcpy(in_mailbox, in_bytes_c, len(in_bytes))
    return in_mailbox


cdef char* _prepare_devx_outbox(outlen):
    """
    Auxiliary function that allocates the outboxes for DevX commands.
    The allocated box must be freed when it's no longer needed.
    :param outlen: Output command's length in bytes
    :return: The C allocated outbox
    """
    cdef char* out_mailbox = <char*>calloc(1, outlen)
    if out_mailbox == NULL:
        raise MemoryError('Failed to allocate memory')
    return out_mailbox


cdef class Mlx5DVPortAttr(PyverbsObject):
    """
    Represents mlx5dv_port struct, which exposes mlx5-specific capabilities,
    reported by mlx5dv_query_port()
    """
    def __init__(self):
        super().__init__()

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('flags', hex(self.attr.flags))

    @property
    def flags(self):
        return self.attr.flags

    @property
    def vport(self):
        return self.attr.vport

    @property
    def vport_vhca_id(self):
        return self.attr.vport_vhca_id

    @property
    def esw_owner_vhca_id(self):
        return self.attr.esw_owner_vhca_id

    @property
    def vport_steering_icm_rx(self):
        return self.attr.vport_steering_icm_rx

    @property
    def vport_steering_icm_tx(self):
        return self.attr.vport_steering_icm_tx

    @property
    def reg_c0_value(self):
        return self.attr.reg_c0.value

    @property
    def reg_c0_mask(self):
        return self.attr.reg_c0.mask


cdef class Mlx5DVContextAttr(PyverbsObject):
    """
    Represent mlx5dv_context_attr struct. This class is used to open an mlx5
    device.
    """
    def __init__(self, flags=0, comp_mask=0):
        super().__init__()
        self.attr.flags = flags
        self.attr.comp_mask = comp_mask

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('flags', self.attr.flags) +\
               print_format.format('comp_mask', self.attr.comp_mask)

    @property
    def flags(self):
        return self.attr.flags
    @flags.setter
    def flags(self, val):
        self.attr.flags = val

    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val


cdef class Mlx5Context(Context):
    """
    Represent mlx5 context, which extends Context.
    """
    def __init__(self, Mlx5DVContextAttr attr not None, name=''):
        """
        Open an mlx5 device using the given attributes
        :param name: The RDMA device's name (used by parent class)
        :param attr: mlx5-specific device attributes
        :return: None
        """
        super().__init__(name=name, attr=attr)
        if not dv.mlx5dv_is_supported(self.device):
            raise PyverbsUserError('This is not an MLX5 device')
        self.context = dv.mlx5dv_open_device(self.device, &attr.attr)
        if self.context == NULL:
            raise PyverbsRDMAErrno('Failed to open mlx5 context on {dev}'
                                   .format(dev=self.name))

    def query_mlx5_device(self, comp_mask=-1):
        """
        Queries the provider for device-specific attributes.
        :param comp_mask: Which attributes to query. Default value is -1. If
                          not changed by user, pyverbs will pass a bitwise OR
                          of all available enum entries.
        :return: A Mlx5DVContext containing the attributes.
        """
        dv_attr = Mlx5DVContext()
        if comp_mask == -1:
            dv_attr.comp_mask = \
                dve.MLX5DV_CONTEXT_MASK_CQE_COMPRESION |\
                dve.MLX5DV_CONTEXT_MASK_SWP |\
                dve.MLX5DV_CONTEXT_MASK_STRIDING_RQ |\
                dve.MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS |\
                dve.MLX5DV_CONTEXT_MASK_DYN_BFREGS |\
                dve.MLX5DV_CONTEXT_MASK_CLOCK_INFO_UPDATE |\
                dve.MLX5DV_CONTEXT_MASK_DC_ODP_CAPS |\
                dve.MLX5DV_CONTEXT_MASK_FLOW_ACTION_FLAGS
        else:
            dv_attr.comp_mask = comp_mask
        rc = dv.mlx5dv_query_device(self.context, &dv_attr.dv)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to query mlx5 device {self.name}.', rc)
        return dv_attr

    @staticmethod
    def query_mlx5_port(Context ctx, port_num):
        dv_attr = Mlx5DVPortAttr()
        rc = dv.mlx5dv_query_port(ctx.context, port_num, &dv_attr.attr)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to query dv port mlx5 {ctx.name} port {port_num}.', rc)
        return dv_attr

    @staticmethod
    def reserved_qpn_alloc(Context ctx):
        """
        Allocate a reserved QP number from firmware.
        :param ctx: The device context to issue the action on.
        :return: The reserved QP number.
        """
        cdef uint32_t qpn
        rc = dv.mlx5dv_reserved_qpn_alloc(ctx.context, &qpn)
        if rc != 0:
            raise PyverbsRDMAError('Failed to alloc reserved QP number.', rc)
        return qpn

    @staticmethod
    def reserved_qpn_dealloc(Context ctx, qpn):
        """
        Release the reserved QP number to firmware.
        :param ctx: The device context to issue the action on.
        :param qpn: The QP number to be deallocated.
        """
        rc = dv.mlx5dv_reserved_qpn_dealloc(ctx.context, qpn)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to dealloc QP number {qpn}.', rc)

    def devx_general_cmd(self, in_, outlen):
        """
        Executes a DevX general command according to the input mailbox.
        :param in_: Bytes of the general command's input data provided in a
                    device specification format.
                    (Stream of bytes or __bytes__ is implemented)
        :param outlen: Expected output length in bytes
        :return out: Bytes of the general command's output data provided in a
                     device specification format
        """
        in_bytes = bytes(in_)
        cdef char *in_mailbox = _prepare_devx_inbox(in_bytes)
        cdef char *out_mailbox = _prepare_devx_outbox(outlen)
        rc = dv.mlx5dv_devx_general_cmd(self.context, in_mailbox, len(in_bytes),
                                        out_mailbox, outlen)
        try:
            if rc:
                raise PyverbsRDMAError("DevX general command failed", rc)
            out = <bytes>out_mailbox[:outlen]
        finally:
            free(in_mailbox)
            free(out_mailbox)
        return out

    @staticmethod
    def device_timestamp_to_ns(Context ctx, device_timestamp):
        """
        Convert device timestamp from HCA core clock units to the corresponding
        nanosecond units. The function uses mlx5dv_get_clock_info to get the
        device clock information.
        :param ctx: The device context to issue the action on.
        :param device_timestamp: The device timestamp to convert.
        :return: Timestamp in nanoseconds
        """
        cdef dv.mlx5dv_clock_info *clock_info
        clock_info = <dv.mlx5dv_clock_info *>calloc(1, sizeof(dv.mlx5dv_clock_info))
        rc = dv.mlx5dv_get_clock_info(ctx.context, clock_info)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to get the clock info', rc)

        ns_time = dv.mlx5dv_ts_to_ns(clock_info, device_timestamp)
        free(clock_info)
        return ns_time

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.context != NULL:
            close_weakrefs([self.pps])
            super(Mlx5Context, self).close()


cdef class Mlx5DVContext(PyverbsObject):
    """
    Represents mlx5dv_context struct, which exposes mlx5-specific capabilities,
    reported by mlx5dv_query_device.
    """
    @property
    def version(self):
        return self.dv.version

    @property
    def flags(self):
        return self.dv.flags

    @property
    def comp_mask(self):
        return self.dv.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.dv.comp_mask = val

    @property
    def cqe_comp_caps(self):
        return self.dv.cqe_comp_caps

    @property
    def sw_parsing_caps(self):
        return self.dv.sw_parsing_caps

    @property
    def striding_rq_caps(self):
        return self.dv.striding_rq_caps

    @property
    def tunnel_offload_caps(self):
        return self.dv.tunnel_offloads_caps

    @property
    def max_dynamic_bfregs(self):
        return self.dv.max_dynamic_bfregs

    @property
    def max_clock_info_update_nsec(self):
        return self.dv.max_clock_info_update_nsec

    @property
    def flow_action_flags(self):
        return self.dv.flow_action_flags

    @property
    def dc_odp_caps(self):
        return self.dv.dc_odp_caps

    @property
    def num_lag_ports(self):
        return self.dv.num_lag_ports

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        ident_format = '  {:20}: {:<20}\n'
        cqe = 'CQE compression caps:\n' +\
              ident_format.format('max num',
                                  self.dv.cqe_comp_caps.max_num) +\
              ident_format.format('supported formats',
                                  cqe_comp_to_str(self.dv.cqe_comp_caps.supported_format))
        swp = 'SW parsing caps:\n' +\
              ident_format.format('SW parsing offloads',
                                  swp_to_str(self.dv.sw_parsing_caps.sw_parsing_offloads)) +\
              ident_format.format('supported QP types',
                                  qpts_to_str(self.dv.sw_parsing_caps.supported_qpts))
        strd = 'Striding RQ caps:\n' +\
               ident_format.format('min single stride log num of bytes',
                                   self.dv.striding_rq_caps.min_single_stride_log_num_of_bytes) +\
               ident_format.format('max single stride log num of bytes',
                                   self.dv.striding_rq_caps.max_single_stride_log_num_of_bytes) +\
               ident_format.format('min single wqe log num of strides',
                                   self.dv.striding_rq_caps.min_single_wqe_log_num_of_strides) +\
               ident_format.format('max single wqe log num of strides',
                                   self.dv.striding_rq_caps.max_single_wqe_log_num_of_strides) +\
               ident_format.format('supported QP types',
                                   qpts_to_str(self.dv.striding_rq_caps.supported_qpts))
        return print_format.format('Version', self.dv.version) +\
               print_format.format('Flags',
                                   context_flags_to_str(self.dv.flags)) +\
               print_format.format('comp mask',
                                   context_comp_mask_to_str(self.dv.comp_mask)) +\
               cqe + swp + strd +\
               print_format.format('Tunnel offloads caps',
                                   tunnel_offloads_to_str(self.dv.tunnel_offloads_caps)) +\
               print_format.format('Max dynamic BF registers',
                                   self.dv.max_dynamic_bfregs) +\
               print_format.format('Max clock info update [nsec]',
                                   self.dv.max_clock_info_update_nsec) +\
               print_format.format('Flow action flags',
                                   self.dv.flow_action_flags) +\
               print_format.format('DC ODP caps', self.dv.dc_odp_caps) +\
               print_format.format('Num LAG ports', self.dv.num_lag_ports)


cdef class Mlx5DVDCInitAttr(PyverbsObject):
    """
    Represents mlx5dv_dc_init_attr struct, which defines initial attributes
    for DC QP creation.
    """
    def __init__(self, dc_type=dve.MLX5DV_DCTYPE_DCI, dct_access_key=0):
        """
        Initializes an Mlx5DVDCInitAttr object with the given DC type and DCT
        access key.
        :param dc_type: Which DC QP to create (DCI/DCT).
        :param dct_access_key: Access key to be used by the DCT
        :return: An initializes object
        """
        super().__init__()
        self.attr.dc_type = dc_type
        self.attr.dct_access_key = dct_access_key

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('DC type', dc_type_to_str(self.attr.dc_type)) +\
               print_format.format('DCT access key', self.attr.dct_access_key)

    @property
    def dc_type(self):
        return self.attr.dc_type
    @dc_type.setter
    def dc_type(self, val):
        self.attr.dc_type = val

    @property
    def dct_access_key(self):
        return self.attr.dct_access_key
    @dct_access_key.setter
    def dct_access_key(self, val):
        self.attr.dct_access_key = val


cdef class Mlx5DVQPInitAttr(PyverbsObject):
    """
    Represents mlx5dv_qp_init_attr struct, initial attributes used for mlx5 QP
    creation.
    """
    def __init__(self, comp_mask=0, create_flags=0,
                 Mlx5DVDCInitAttr dc_init_attr=None, send_ops_flags=0):
        """
        Initializes an Mlx5DVQPInitAttr object with the given user data.
        :param comp_mask: A bitmask specifying which fields are valid
        :param create_flags: A bitwise OR of mlx5dv_qp_create_flags
        :param dc_init_attr: Mlx5DVDCInitAttr object
        :param send_ops_flags: A bitwise OR of mlx5dv_qp_create_send_ops_flags
        :return: An initialized Mlx5DVQPInitAttr object
        """
        super().__init__()
        self.attr.comp_mask = comp_mask
        self.attr.create_flags = create_flags
        self.attr.send_ops_flags = send_ops_flags
        if dc_init_attr is not None:
            self.attr.dc_init_attr.dc_type = dc_init_attr.dc_type
            self.attr.dc_init_attr.dct_access_key = dc_init_attr.dct_access_key

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('Comp mask',
                                   qp_comp_mask_to_str(self.attr.comp_mask)) +\
               print_format.format('Create flags',
                                   qp_create_flags_to_str(self.attr.create_flags)) +\
               'DC init attr:\n' +\
               print_format.format('  DC type',
                                   dc_type_to_str(self.attr.dc_init_attr.dc_type)) +\
               print_format.format('  DCT access key',
                                   self.attr.dc_init_attr.dct_access_key) +\
               print_format.format('Send ops flags',
                                   send_ops_flags_to_str(self.attr.send_ops_flags))

    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val

    @property
    def create_flags(self):
        return self.attr.create_flags
    @create_flags.setter
    def create_flags(self, val):
        self.attr.create_flags = val

    @property
    def send_ops_flags(self):
        return self.attr.send_ops_flags
    @send_ops_flags.setter
    def send_ops_flags(self, val):
        self.attr.send_ops_flags = val

    @property
    def dc_type(self):
        return self.attr.dc_init_attr.dc_type
    @dc_type.setter
    def dc_type(self, val):
        self.attr.dc_init_attr.dc_type = val

    @property
    def dct_access_key(self):
        return self.attr.dc_init_attr.dct_access_key
    @dct_access_key.setter
    def dct_access_key(self, val):
        self.attr.dc_init_attr.dct_access_key = val


cdef class Mlx5QP(QPEx):
    def __init__(self, Context context, QPInitAttrEx init_attr,
                 Mlx5DVQPInitAttr dv_init_attr):
        """
        Initializes an mlx5 QP according to the user-provided data.
        :param context: Context object
        :param init_attr: QPInitAttrEx object
        :param dv_init_attr: Mlx5DVQPInitAttr object
        :return: An initialized Mlx5QP
        """
        cdef PD pd

        # Initialize the logger here as the parent's __init__ is called after
        # the QP is allocated. Allocation can fail, which will lead to exceptions
        # thrown during object's teardown.
        self.logger = logging.getLogger(self.__class__.__name__)
        self.dc_type = dv_init_attr.dc_type if dv_init_attr else 0
        if init_attr.pd is not None:
            pd = <PD>init_attr.pd
            pd.add_ref(self)
        self.qp = \
            dv.mlx5dv_create_qp(context.context,
                                &init_attr.attr,
                                &dv_init_attr.attr if dv_init_attr is not None
                                else NULL)
        if self.qp == NULL:
            raise PyverbsRDMAErrno('Failed to create MLX5 QP.\nQPInitAttrEx '
                                   'attributes:\n{}\nMLX5DVQPInitAttr:\n{}'.
                                   format(init_attr, dv_init_attr))
        super().__init__(context, init_attr)

    def _get_comp_mask(self, dst):
        masks = {dve.MLX5DV_DCTYPE_DCT: {'INIT': e.IBV_QP_PKEY_INDEX |
                                         e.IBV_QP_PORT | e.IBV_QP_ACCESS_FLAGS,
                                         'RTR': e.IBV_QP_AV |\
                                         e.IBV_QP_PATH_MTU |\
                                         e.IBV_QP_MIN_RNR_TIMER},
                 dve.MLX5DV_DCTYPE_DCI: {'INIT': e.IBV_QP_PKEY_INDEX |\
                                         e.IBV_QP_PORT,
                                         'RTR': e.IBV_QP_PATH_MTU,
                                         'RTS': e.IBV_QP_TIMEOUT |\
                                         e.IBV_QP_RETRY_CNT |\
                                         e.IBV_QP_RNR_RETRY | e.IBV_QP_SQ_PSN |\
                                         e.IBV_QP_MAX_QP_RD_ATOMIC}}
        if self.dc_type == 0:
            return super()._get_comp_mask(dst)
        return masks[self.dc_type][dst] | e.IBV_QP_STATE

    def wr_set_dc_addr(self, AH ah, remote_dctn, remote_dc_key):
        """
        Attach a DC info to the last work request.
        :param ah: Address Handle to the requested DCT.
        :param remote_dctn: The remote DCT number.
        :param remote_dc_key: The remote DC key.
        """
        dv.mlx5dv_wr_set_dc_addr(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                                 ah.ah, remote_dctn, remote_dc_key)

    @staticmethod
    def query_lag_port(QP qp):
        """
        Queries for port num that the QP desired to use, and the port that
        is currently used by the bond for this QP.
        :param qp: Queries the port for this QP.
        :return: Tuple of the desired port and actual port which used by the HW.
        """
        cdef uint8_t port_num
        cdef uint8_t active_port_num
        rc = dv.mlx5dv_query_qp_lag_port(qp.qp, &port_num, &active_port_num)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to query QP #{qp.qp.qp_num}', rc)
        return port_num, active_port_num

    @staticmethod
    def modify_lag_port(QP qp, uint8_t port_num):
        """
        Modifies the lag port num that the QP desires to use.
        :param qp: Modifies the port for this QP.
        :param port_num: The desired port to be used by the QP to send traffic
                         in a LAG configuration.
        """
        rc = dv.mlx5dv_modify_qp_lag_port(qp.qp, port_num)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to modify lag of QP #{qp.qp.qp_num}', rc)

    @staticmethod
    def modify_qp_sched_elem(QP qp, Mlx5dvSchedLeaf req_sched_leaf=None,
                             Mlx5dvSchedLeaf resp_sched_leaf=None):
        """
        Connect a QP with a requestor and/or a responder scheduling element.
        :param qp: connect this QP to schedule elements.
        :param req_sched_leaf: Mlx5dvSchedLeaf for the send queue.
        :param resp_sched_leaf: Mlx5dvSchedLeaf for the recv queue.
        """
        req_se = req_sched_leaf.sched_leaf if req_sched_leaf else NULL
        resp_se = resp_sched_leaf.sched_leaf if resp_sched_leaf else NULL
        rc = dv.mlx5dv_modify_qp_sched_elem(qp.qp, req_se, resp_se)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to modify QP #{qp.qp.qp_num} sched element', rc)

    @staticmethod
    def modify_udp_sport(QP qp, uint16_t udp_sport):
        """
        Modifies the UDP source port of a given QP.
        :param qp: A QP in RTS state to modify its UDP sport.
        :param udp_sport: The desired UDP sport to be used by the QP.
        """
        rc = dv.mlx5dv_modify_qp_udp_sport(qp.qp, udp_sport)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to modify UDP source port of QP '
                                   f'#{qp.qp.qp_num}', rc)


cdef class Mlx5DVCQInitAttr(PyverbsObject):
    """
    Represents mlx5dv_cq_init_attr struct, initial attributes used for mlx5 CQ
    creation.
    """
    def __init__(self, comp_mask=0, cqe_comp_res_format=0, flags=0, cqe_size=0):
        """
        Initializes an Mlx5CQInitAttr object with zeroes as default values.
        :param comp_mask: Marks which of the following fields should be
                          considered. Use mlx5dv_cq_init_attr_mask enum.
        :param cqe_comp_res_format: The various CQE response formats of the
                                    responder side. Use
                                    mlx5dv_cqe_comp_res_format enum.
        :param flags: A bitwise OR of the various values described in
                      mlx5dv_cq_init_attr_flags.
        :param cqe_size: Configure the CQE size to be 64 or 128 bytes, other
                         values will cause the CQ creation process to fail.
                         Valid when MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE is set.
        :return: None
        """
        super().__init__()
        self.attr.comp_mask = comp_mask
        self.attr.cqe_comp_res_format = cqe_comp_res_format
        self.attr.flags = flags
        self.attr.cqe_size = cqe_size

    @property
    def comp_mask(self):
        return self.attr.comp_mask
    @comp_mask.setter
    def comp_mask(self, val):
        self.attr.comp_mask = val

    @property
    def cqe_comp_res_format(self):
        return self.attr.cqe_comp_res_format
    @cqe_comp_res_format.setter
    def cqe_comp_res_format(self, val):
        self.attr.cqe_comp_res_format = val

    @property
    def flags(self):
        return self.attr.flags
    @flags.setter
    def flags(self, val):
        self.attr.flags = val

    @property
    def cqe_size(self):
        return self.attr.cqe_size
    @cqe_size.setter
    def cqe_size(self, val):
        self.attr.cqe_size = val

    def __str__(self):
        print_format = '{:22}: {:<20}\n'
        flags = {dve.MLX5DV_CQ_INIT_ATTR_FLAGS_CQE_PAD:
                     "MLX5DV_CQ_INIT_ATTR_FLAGS_CQE_PAD}"}
        mask = {dve.MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE:
                    "MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE",
                dve.MLX5DV_CQ_INIT_ATTR_MASK_FLAGS:
                    "MLX5DV_CQ_INIT_ATTR_MASK_FLAGS",
                dve.MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE:
                    "MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE"}
        fmt = {dve.MLX5DV_CQE_RES_FORMAT_HASH: "MLX5DV_CQE_RES_FORMAT_HASH",
               dve.MLX5DV_CQE_RES_FORMAT_CSUM: "MLX5DV_CQE_RES_FORMAT_CSUM",
               dve.MLX5DV_CQE_RES_FORMAT_CSUM_STRIDX:
                   "MLX5DV_CQE_RES_FORMAT_CSUM_STRIDX"}

        return 'Mlx5DVCQInitAttr:\n' +\
               print_format.format('comp_mask', bitmask_to_str(self.comp_mask,
                                                               mask)) +\
               print_format.format('CQE compression format',
                                   bitmask_to_str(self.cqe_comp_res_format,
                                                  fmt)) +\
               print_format.format('flags', bitmask_to_str(self.flags,
                                                           flags)) + \
               print_format.format('CQE size', self.cqe_size)


cdef class Mlx5CQ(CQEX):
    def __init__(self, Mlx5Context context, CqInitAttrEx init_attr,
                 Mlx5DVCQInitAttr dv_init_attr):
        # Initialize the logger here as the parent's __init__ is called after
        # the CQ is allocated. Allocation can fail, which will lead to exceptions
        # thrown during object's teardown.
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cq = \
            dv.mlx5dv_create_cq(context.context, &init_attr.attr,
                                &dv_init_attr.attr if dv_init_attr is not None
                                else NULL)
        if self.cq == NULL:
            raise PyverbsRDMAErrno('Failed to create MLX5 CQ.\nCQInitAttrEx:\n'
                                   '{}\nMLX5DVCQInitAttr:\n{}'.
                                   format(init_attr, dv_init_attr))
        self.ibv_cq = v.ibv_cq_ex_to_cq(self.cq)
        self.context = context
        context.add_ref(self)
        super().__init__(context, init_attr)

    def __str__(self):
        print_format = '{:<22}: {:<20}\n'
        return 'Mlx5 CQ:\n' +\
               print_format.format('Handle', self.cq.handle) +\
               print_format.format('CQEs', self.cq.cqe)


def qpts_to_str(qp_types):
    numeric_types = qp_types
    qpts_str = ''
    qpts = {e.IBV_QPT_RC: 'RC', e.IBV_QPT_UC: 'UC', e.IBV_QPT_UD: 'UD',
            e.IBV_QPT_RAW_PACKET: 'Raw Packet', e.IBV_QPT_XRC_SEND: 'XRC Send',
            e.IBV_QPT_XRC_RECV: 'XRC Recv', e.IBV_QPT_DRIVER: 'Driver QPT'}
    for t in qpts.keys():
        if (1 << t) & qp_types:
            qpts_str += qpts[t] + ', '
            qp_types -= t
        if qp_types == 0:
            break
    return qpts_str[:-2] + ' ({})'.format(numeric_types)


def bitmask_to_str(bits, values):
    numeric_bits = bits
    res = ''
    for t in values.keys():
        if t & bits:
            res += values[t] + ', '
            bits -= t
        if bits == 0:
            break
    return res[:-2] + ' ({})'.format(numeric_bits) # Remove last comma and space


def context_comp_mask_to_str(mask):
    l = {dve.MLX5DV_CONTEXT_MASK_CQE_COMPRESION: 'CQE compression',
         dve.MLX5DV_CONTEXT_MASK_SWP: 'SW parsing',
         dve.MLX5DV_CONTEXT_MASK_STRIDING_RQ: 'Striding RQ',
         dve.MLX5DV_CONTEXT_MASK_TUNNEL_OFFLOADS: 'Tunnel offloads',
         dve.MLX5DV_CONTEXT_MASK_DYN_BFREGS: 'Dynamic BF regs',
         dve.MLX5DV_CONTEXT_MASK_CLOCK_INFO_UPDATE: 'Clock info update',
         dve.MLX5DV_CONTEXT_MASK_FLOW_ACTION_FLAGS: 'Flow action flags'}
    return bitmask_to_str(mask, l)


def context_flags_to_str(flags):
    l = {dve.MLX5DV_CONTEXT_FLAGS_CQE_V1: 'CQE v1',
         dve.MLX5DV_CONTEXT_FLAGS_MPW_ALLOWED: 'Multi packet WQE allowed',
         dve.MLX5DV_CONTEXT_FLAGS_ENHANCED_MPW: 'Enhanced multi packet WQE',
         dve.MLX5DV_CONTEXT_FLAGS_CQE_128B_COMP: 'Support CQE 128B compression',
         dve.MLX5DV_CONTEXT_FLAGS_CQE_128B_PAD: 'Support CQE 128B padding',
         dve.MLX5DV_CONTEXT_FLAGS_PACKET_BASED_CREDIT_MODE:
         'Support packet based credit mode (in RC QP)'}
    return bitmask_to_str(flags, l)


def swp_to_str(swps):
    l = {dve.MLX5DV_SW_PARSING: 'SW Parsing',
         dve.MLX5DV_SW_PARSING_CSUM: 'SW Parsing CSUM',
         dve.MLX5DV_SW_PARSING_LSO: 'SW Parsing LSO'}
    return bitmask_to_str(swps, l)


def cqe_comp_to_str(cqe):
    l = {dve.MLX5DV_CQE_RES_FORMAT_HASH: 'with hash',
         dve.MLX5DV_CQE_RES_FORMAT_CSUM: 'with RX checksum CSUM',
         dve.MLX5DV_CQE_RES_FORMAT_CSUM_STRIDX: 'with stride index'}
    return bitmask_to_str(cqe, l)


def tunnel_offloads_to_str(tun):
    l = {dve.MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_VXLAN: 'VXLAN',
         dve.MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GRE: 'GRE',
         dve.MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GENEVE: 'Geneve',
         dve.MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_CW_MPLS_OVER_GRE:\
         'Ctrl word + MPLS over GRE',
         dve.MLX5DV_RAW_PACKET_CAP_TUNNELED_OFFLOAD_CW_MPLS_OVER_UDP:\
         'Ctrl word + MPLS over UDP'}
    return bitmask_to_str(tun, l)


def dc_type_to_str(dctype):
    l = {dve.MLX5DV_DCTYPE_DCT: 'DCT', dve.MLX5DV_DCTYPE_DCI: 'DCI'}
    try:
        return l[dctype]
    except KeyError:
        return 'Unknown DC type ({dc})'.format(dc=dctype)


def qp_comp_mask_to_str(flags):
    l = {dve.MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS: 'Create flags',
         dve.MLX5DV_QP_INIT_ATTR_MASK_DC: 'DC',
         dve.MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS: 'Send ops flags'}
    return bitmask_to_str(flags, l)


def qp_create_flags_to_str(flags):
    l = {dve.MLX5DV_QP_CREATE_TUNNEL_OFFLOADS: 'Tunnel offloads',
         dve.MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_UC:
             'Allow UC self loopback',
         dve.MLX5DV_QP_CREATE_TIR_ALLOW_SELF_LOOPBACK_MC:
             'Allow MC self loopback',
         dve.MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE: 'Disable scatter to CQE',
         dve.MLX5DV_QP_CREATE_ALLOW_SCATTER_TO_CQE: 'Allow scatter to CQE',
         dve.MLX5DV_QP_CREATE_PACKET_BASED_CREDIT_MODE:
             'Packet based credit mode'}
    return bitmask_to_str(flags, l)


def send_ops_flags_to_str(flags):
    l = {dve.MLX5DV_QP_EX_WITH_MR_INTERLEAVED: 'With MR interleaved',
         dve.MLX5DV_QP_EX_WITH_MR_LIST: 'With MR list'}
    return bitmask_to_str(flags, l)


cdef class Mlx5VAR(PyverbsObject):
    def __init__(self, Context context not None, flags=0):
        self.context = context
        self.var = dv.mlx5dv_alloc_var(context.context, flags)
        if self.var == NULL:
            raise PyverbsRDMAErrno('Failed to allocate VAR')
        context.vars.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.var != NULL:
            dv.mlx5dv_free_var(self.var)
            self.var = NULL

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('page id', self.var.page_id) +\
               print_format.format('length', self.var.length) +\
               print_format.format('mmap offset', self.var.mmap_off) +\
               print_format.format('compatibility mask', self.var.comp_mask)

    @property
    def page_id(self):
        return self.var.page_id

    @property
    def length(self):
        return self.var.length

    @property
    def mmap_off(self):
        return self.var.mmap_off

    @property
    def comp_mask(self):
        return self.var.comp_mask


cdef class Mlx5PP(PyverbsObject):
    """
    Represents mlx5dv_pp, packet pacing struct.
    """
    def __init__(self, Context context not None, pp_context, flags=0):
        """
        Initializes a Mlx5PP object.
        :param context: DevX context
        :param pp_context: Bytes of packet pacing context according to the
                           device specs. Must be bytes type or implements
                           __bytes__ method
        :param flags: Packet pacing allocation flags
        """
        self.context = context
        pp_ctx_bytes = bytes(pp_context)
        self.pp = dv.mlx5dv_pp_alloc(context.context, len(pp_ctx_bytes),
                                     <char*>pp_ctx_bytes, flags)
        if self.pp == NULL:
            raise PyverbsRDMAErrno('Failed to allocate packet pacing entry')
        context.pps.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.pp != NULL:
            dv.mlx5dv_pp_free(self.pp)
            self.pp = NULL

    @property
    def index(self):
        return self.pp.index


cdef class Mlx5UAR(PyverbsObject):
    def __init__(self, Context context not None, flags=0):
        self.uar = dv.mlx5dv_devx_alloc_uar(context.context, flags)
        if self.uar == NULL:
            raise PyverbsRDMAErrno('Failed to allocate UAR')
        context.uars.add(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.uar != NULL:
            dv.mlx5dv_devx_free_uar(self.uar)
            self.uar = NULL

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('reg addr', <uintptr_t>self.uar.reg_addr) +\
               print_format.format('base addr', <uintptr_t>self.uar.base_addr) +\
               print_format.format('page id', self.uar.page_id) +\
               print_format.format('mmap off', self.uar.mmap_off) +\
               print_format.format('comp mask', self.uar.comp_mask)

    @property
    def reg_addr(self):
        return <uintptr_t>self.uar.reg_addr

    @property
    def base_addr(self):
        return <uintptr_t>self.uar.base_addr

    @property
    def page_id(self):
        return self.uar.page_id

    @property
    def mmap_off(self):
        return self.uar.mmap_off

    @property
    def comp_mask(self):
        return self.uar.comp_mask


cdef class Mlx5DmOpAddr(PyverbsCM):
    def __init__(self, DM dm not None, op=0):
        """
        Wraps mlx5dv_dm_map_op_addr.
        Gets operation address of a device memory (DM), which must be munmapped by
        the user when it's no longer needed.
        :param dm: Device Memory instance
        :param op: DM operation type
        :return: An mmaped address to the DM for the requested operation (op).
        """
        self.addr = dv.mlx5dv_dm_map_op_addr(dm.dm, op)
        if self.addr == NULL:
            raise PyverbsRDMAErrno('Failed to get DM operation address')

    def unmap(self, length):
        munmap(self.addr, length)

    def write(self, data):
        """
        Writes data (bytes) to the DM operation address using memcpy.
        :param data: Bytes of data
        """
        memcpy(<char *>self.addr, <char *>data, len(data))

    def read(self, length):
        """
        Reads 'length' bytes from the DM operation address using memcpy.
        :param length: Data length to read (in bytes)
        :return: Read data in bytes
        """
        cdef char *data = <char*> calloc(length, sizeof(char))
        if data == NULL:
            raise PyverbsError('Failed to allocate memory')
        memcpy(<char *>data, <char *>self.addr, length)
        res = data[:length]
        free(data)
        return res

    cpdef close(self):
        self.addr = NULL

    @property
    def addr(self):
        return <uintptr_t>self.addr
