# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

from pyverbs.pyverbs_error import PyverbsUserError
cimport pyverbs.providers.mlx5.mlx5dv_enums as dve
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base import PyverbsRDMAErrno
cimport pyverbs.libibverbs_enums as e


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


def qpts_to_str(qp_types):
    numberic_types = qp_types
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
    return qpts_str[:-2] + ' ({})'.format(numberic_types)


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
