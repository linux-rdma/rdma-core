# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

from pyverbs.pyverbs_error import PyverbsUserError
cimport pyverbs.providers.mlx5.mlx5dv_enums as dve
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base import PyverbsRDMAErrno
cimport pyverbs.libibverbs_enums as e
from pyverbs.qp cimport QPInitAttrEx
from pyverbs.pd cimport PD

cdef class Mlx5DVContextAttr(PyverbsObject):
    """
    Represent mlx5dv_context_attr struct. This class is used to open an mlx5
    device.
    """
    def __cinit__(self, flags=0, comp_mask=0):
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
    def __cinit__(self, **kwargs):
        """
        Open an mlx5 device using the given attributes
        :param kwargs: Arguments:
            * *name* (str)
               The RDMA device's name (used by parent class)
            * *attr* (Mlx5DVContextAttr)
               mlx5-specific device attributes
        :return: None
        """
        cdef Mlx5DVContextAttr attr
        attr = kwargs.get('attr')
        if not attr or not isinstance(attr, Mlx5DVContextAttr):
            raise PyverbsUserError('Missing provider attributes')
        if not dv.mlx5dv_is_supported(self.device):
            raise PyverbsUserError('This is not an MLX5 device')
        self.context = dv.mlx5dv_open_device(self.device, &attr.attr)

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
                dve.MLX5DV_CONTEXT_MASK_FLOW_ACTION_FLAGS
        else:
            dv_attr.comp_mask = comp_mask
        rc = dv.mlx5dv_query_device(self.context, &dv_attr.dv)
        if rc != 0:
            raise PyverbsRDMAErrno('Failed to query mlx5 device {name}, got {rc}'.
                                   format(name=self.name, rc=rc))
        return dv_attr


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
               print_format.format('DC ODP caps', self.dv.dc_odp_caps)


cdef class Mlx5DVDCInitAttr(PyverbsObject):
    """
    Represents mlx5dv_dc_init_attr struct, which defines initial attributes
    for DC QP creation.
    """
    def __cinit__(self, dc_type=dve.MLX5DV_DCTYPE_DCI, dct_access_key=0):
        """
        Initializes an Mlx5DVDCInitAttr object with the given DC type and DCT
        access key.
        :param dc_type: Which DC QP to create (DCI/DCT).
        :param dct_access_key: Access key to be used by the DCT
        :return: An initializes object
        """
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
    def __cinit__(self, comp_mask=0, create_flags=0,
                  Mlx5DVDCInitAttr dc_init_attr=None, send_ops_flags=0):
        """
        Initializes an Mlx5DVQPInitAttr object with the given user data.
        :param comp_mask: A bitmask specifying which fields are valid
        :param create_flags: A bitwise OR of mlx5dv_qp_create_flags
        :param dc_init_attr: Mlx5DVDCInitAttr object
        :param send_ops_flags: A bitwise OR of mlx5dv_qp_create_send_ops_flags
        :return: An initialized Mlx5DVQPInitAttr object
        """
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


cdef class Mlx5QP(QP):
    def __cinit__(self, Mlx5Context context, QPInitAttrEx init_attr,
                  Mlx5DVQPInitAttr dv_init_attr):
        """
        Initializes an mlx5 QP according to the user-provided data.
        :param context: mlx5 Context object
        :param init_attr: QPInitAttrEx object
        :param dv_init_attr: Mlx5DVQPInitAttr object
        :return: An initialized Mlx5QP
        """
        cdef PD pd
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
