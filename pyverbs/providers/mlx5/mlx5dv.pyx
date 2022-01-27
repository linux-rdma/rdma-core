# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file

from libc.stdint cimport uintptr_t, uint8_t, uint16_t, uint32_t
from libc.string cimport memcpy, memset
from libc.stdlib cimport calloc, free
from posix.mman cimport munmap
import logging
import weakref

from pyverbs.providers.mlx5.mlx5dv_mkey cimport Mlx5MrInterleaved, Mlx5Mkey, \
    Mlx5MkeyConfAttr, Mlx5SigBlockAttr
from pyverbs.providers.mlx5.mlx5dv_crypto cimport Mlx5CryptoLoginAttr, Mlx5CryptoAttr
from pyverbs.pyverbs_error import PyverbsUserError, PyverbsRDMAError, PyverbsError
from pyverbs.providers.mlx5.dr_action cimport DrActionFlowCounter
from pyverbs.providers.mlx5.mlx5dv_sched cimport Mlx5dvSchedLeaf
cimport pyverbs.providers.mlx5.mlx5dv_enums as dve
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.mem_alloc import posix_memalign
from pyverbs.qp cimport QPInitAttrEx, QPEx
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.base cimport close_weakrefs
from pyverbs.wr cimport copy_sg_array
cimport pyverbs.libibverbs_enums as e
from pyverbs.cq cimport CqInitAttrEx
cimport pyverbs.libibverbs as v
from pyverbs.device cimport DM
from pyverbs.addr cimport AH
from pyverbs.pd cimport PD


cdef extern from 'endian.h':
    unsigned long htobe16(unsigned long host_16bits)
    unsigned long be16toh(unsigned long network_16bits)
    unsigned long htobe32(unsigned long host_32bits)
    unsigned long be32toh(unsigned long network_32bits)
    unsigned long htobe64(unsigned long host_64bits)
    unsigned long be64toh(unsigned long network_64bits)


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


cdef class Mlx5DevxObj(PyverbsCM):
    """
    Represents mlx5dv_devx_obj C struct.
    """
    def __init__(self, Context context, in_, outlen):
        """
        Creates a DevX object.
        If the object was successfully created, the command's output would be
        stored as a memoryview in self.out_view.
        :param in_: Bytes of the obj_create command's input data provided in a
                    device specification format.
                    (Stream of bytes or __bytes__ is implemented)
        :param outlen: Expected output length in bytes
        """
        super().__init__()
        in_bytes = bytes(in_)
        cdef char *in_mailbox = _prepare_devx_inbox(in_bytes)
        cdef char *out_mailbox = _prepare_devx_outbox(outlen)
        self.obj = dv.mlx5dv_devx_obj_create(context.context, in_mailbox,
                                             len(in_bytes), out_mailbox, outlen)
        try:
            if self.obj == NULL:
                raise PyverbsRDMAErrno('Failed to create DevX object')
            self.out_view = memoryview(out_mailbox[:outlen])
            status = hex(self.out_view[0])
            syndrome = self.out_view[4:8].hex()
            if status != hex(0):
                raise PyverbsRDMAError('Failed to create DevX object with status'
                                       f'({status}) and syndrome (0x{syndrome})')
        finally:
            free(in_mailbox)
            free(out_mailbox)
        self.context = context
        self.context.add_ref(self)
        self.flow_counter_actions = weakref.WeakSet()

    def query(self, in_, outlen):
        """
        Queries the DevX object.
        :param in_: Bytes of the obj_query command's input data provided in a
                    device specification format.
                    (Stream of bytes or __bytes__ is implemented)
        :param outlen: Expected output length in bytes
        :return: Bytes of the command's output
        """
        in_bytes = bytes(in_)
        cdef char *in_mailbox = _prepare_devx_inbox(in_bytes)
        cdef char *out_mailbox = _prepare_devx_outbox(outlen)
        rc = dv.mlx5dv_devx_obj_query(self.obj, in_mailbox, len(in_bytes),
                                      out_mailbox, outlen)
        try:
            if rc:
                raise PyverbsRDMAError('Failed to query DevX object', rc)
            out = <bytes>out_mailbox[:outlen]
        finally:
            free(in_mailbox)
            free(out_mailbox)
        return out

    def modify(self, in_, outlen):
        """
        Modifies the DevX object.
        :param in_: Bytes of the obj_modify command's input data provided in a
                    device specification format.
                    (Stream of bytes or __bytes__ is implemented)
        :param outlen: Expected output length in bytes
        :return: Bytes of the command's output
        """
        in_bytes = bytes(in_)
        cdef char *in_mailbox = _prepare_devx_inbox(in_bytes)
        cdef char *out_mailbox = _prepare_devx_outbox(outlen)
        rc = dv.mlx5dv_devx_obj_modify(self.obj, in_mailbox, len(in_bytes),
                                       out_mailbox, outlen)
        try:
            if rc:
                raise PyverbsRDMAError('Failed to modify DevX object', rc)
            out = <bytes>out_mailbox[:outlen]
        finally:
            free(in_mailbox)
            free(out_mailbox)
        return out

    cdef add_ref(self, obj):
        if isinstance(obj, DrActionFlowCounter):
            self.flow_counter_actions.add(obj)
        else:
            raise PyverbsError('Unrecognized object type')

    @property
    def out_view(self):
        return self.out_view

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.obj != NULL:
            self.logger.debug('Closing Mlx5DvexObj')
            close_weakrefs([self.flow_counter_actions])
            rc = dv.mlx5dv_devx_obj_destroy(self.obj)
            if rc:
                raise PyverbsRDMAError('Failed to destroy a DevX object', rc)
            self.obj = NULL
            self.context = None


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
        self.devx_umems = weakref.WeakSet()
        self.devx_objs = weakref.WeakSet()

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
                dve.MLX5DV_CONTEXT_MASK_FLOW_ACTION_FLAGS |\
                dve.MLX5DV_CONTEXT_MASK_DCI_STREAMS |\
                dve.MLX5DV_CONTEXT_MASK_WR_MEMCPY_LENGTH |\
                dve.MLX5DV_CONTEXT_MASK_CRYPTO_OFFLOAD
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

    @staticmethod
    def crypto_login(Context ctx, Mlx5CryptoLoginAttr login_attr):
        """
        Creates a crypto login session
        :param ctx: The device context to issue the action on.
        :param login_attr: Mlx5CryptoLoginAttr object which contains the
                           credential to login with and the import KEK to be
                           used for secured communications.
        """
        rc = dv.mlx5dv_crypto_login(ctx.context, &login_attr.mlx5dv_crypto_login_attr)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to create crypto login session.', rc)

    @staticmethod
    def query_login_state(Context ctx):
        """
        Queries the state of the current crypto login session.
        :param ctx: The device context to issue the action on.
        :return: The login state.
        """
        cdef dv.mlx5dv_crypto_login_state state
        rc = dv.mlx5dv_crypto_login_query_state(ctx.context, &state)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to query the crypto login session state.', rc)
        return state

    @staticmethod
    def crypto_logout(Context ctx):
        """
        Logs out from the current crypto login session.
        :param ctx: The device context to issue the action on.
        """
        rc = dv.mlx5dv_crypto_logout(ctx.context)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to logout from crypto login session.', rc)

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

    def devx_query_eqn(self, vector):
        """
        Query EQN for a given vector id.
        :param vector: Completion vector number
        :return: The device EQ number which relates to the given input vector
        """
        cdef uint32_t eqn
        rc = dv.mlx5dv_devx_query_eqn(self.context, vector, &eqn)
        if rc:
            raise PyverbsRDMAError('Failed to query EQN', rc)
        return eqn

    cdef add_ref(self, obj):
        try:
            Context.add_ref(self, obj)
        except PyverbsError:
            if isinstance(obj, Mlx5UMEM):
                self.devx_umems.add(obj)
            elif isinstance(obj, Mlx5DevxObj):
                self.devx_objs.add(obj)
            else:
                raise PyverbsError('Unrecognized object type')

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.context != NULL:
            close_weakrefs([self.pps, self.devx_objs, self.devx_umems])
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
    def crypto_caps(self):
        return self.dv.crypto_caps

    @property
    def num_lag_ports(self):
        return self.dv.num_lag_ports

    @property
    def dci_streams_caps(self):
        return self.dv.dci_streams_caps

    @property
    def max_wr_memcpy_length(self):
        return self.dv.max_wr_memcpy_length

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
        stream = 'DCI stream caps:\n' +\
                  ident_format.format('max log num concurrent streams',
                                      self.dv.dci_streams_caps.max_log_num_concurent) +\
                  ident_format.format('max log num errored streams',
                                      self.dv.dci_streams_caps.max_log_num_errored)
        return print_format.format('Version', self.dv.version) +\
               print_format.format('Flags',
                                   context_flags_to_str(self.dv.flags)) +\
               print_format.format('comp mask',
                                   context_comp_mask_to_str(self.dv.comp_mask)) +\
               cqe + swp + strd + stream +\
               print_format.format('Tunnel offloads caps',
                                   tunnel_offloads_to_str(self.dv.tunnel_offloads_caps)) +\
               print_format.format('Max dynamic BF registers',
                                   self.dv.max_dynamic_bfregs) +\
               print_format.format('Max clock info update [nsec]',
                                   self.dv.max_clock_info_update_nsec) +\
               print_format.format('Flow action flags',
                                   self.dv.flow_action_flags) +\
               print_format.format('DC ODP caps', self.dv.dc_odp_caps) +\
               print_format.format('Num LAG ports', self.dv.num_lag_ports) +\
               print_format.format('Max WR memcpy length', self.dv.max_wr_memcpy_length)


cdef class Mlx5DCIStreamInitAttr(PyverbsObject):
    """
    Represents dci_streams struct, which defines initial attributes
    for DC QP creation.
    """
    def __init__(self, log_num_concurent=0, log_num_errored=0):
        """
        Initializes an Mlx5DCIStreamInitAttr object with the given DC
        log_num_concurent and log_num_errored.
        :param log_num_concurent: Number of dci stream channels.
        :param log_num_errored: Number of dci error stream channels
                                before moving DCI to error.
        :return: An initialized object
        """
        super().__init__()
        self.dci_streams.log_num_concurent = log_num_concurent
        self.dci_streams.log_num_errored = log_num_errored

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('DCI Stream log_num_concurent', self.dci_streams.log_num_concurent) +\
               print_format.format('DCI Stream log_num_errored', self.dci_streams.log_num_errored)

    @property
    def log_num_concurent(self):
        return self.dci_streams.log_num_concurent
    @log_num_concurent.setter
    def log_num_concurent(self, val):
        self.dci_streams.log_num_concurent=val

    @property
    def log_num_errored(self):
        return self.dci_streams.log_num_errored
    @log_num_errored.setter
    def log_num_errored(self, val):
        self.dci_streams.log_num_errored=val


cdef class Mlx5DVDCInitAttr(PyverbsObject):
    """
    Represents mlx5dv_dc_init_attr struct, which defines initial attributes
    for DC QP creation.
    """
    def __init__(self, dc_type=dve.MLX5DV_DCTYPE_DCI, dct_access_key=0, dci_streams=None):
        """
        Initializes an Mlx5DVDCInitAttr object with the given DC type and DCT
        access key.
        :param dc_type: Which DC QP to create (DCI/DCT).
        :param dct_access_key: Access key to be used by the DCT
        :param dci_streams: Mlx5DCIStreamInitAttr
        :return: An initializes object
        """
        super().__init__()
        self.attr.dc_type = dc_type
        self.attr.dct_access_key = dct_access_key
        if dci_streams is not None:
            self.attr.dci_streams.log_num_concurent=dci_streams.log_num_concurent
            self.attr.dci_streams.log_num_errored=dci_streams.log_num_errored

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('DC type', dc_type_to_str(self.attr.dc_type)) +\
               print_format.format('DCT access key', self.attr.dct_access_key) +\
               print_format.format('DCI Stream log_num_concurent', self.attr.dci_streams.log_num_concurent) +\
               print_format.format('DCI Stream log_num_errored', self.attr.dci_streams.log_num_errored)

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

    @property
    def dci_streams(self):
        return self.attr.dci_streams
    @dci_streams.setter
    def dci_streams(self, val):
        self.attr.dci_streams=val

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
            if comp_mask & dve.MLX5DV_QP_INIT_ATTR_MASK_DCI_STREAMS:
                self.attr.dc_init_attr.dci_streams = dc_init_attr.dci_streams
            else:
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
               print_format.format('  DCI Stream log_num_concurent',
                                   self.attr.dc_init_attr.dci_streams.log_num_concurent) +\
               print_format.format('  DCI Stream log_num_errored',
                                   self.attr.dc_init_attr.dci_streams.log_num_errored) +\
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

    @property
    def dci_streams(self):
        return self.attr.dc_init_attr.dci_streams
    @dci_streams.setter
    def dci_streams(self, val):
        self.attr.dc_init_attr.dci_streams=val


cdef copy_mr_interleaved_array(dv.mlx5dv_mr_interleaved *mr_interleaved_p,
                               mr_interleaved_lst):
    """
    Build C array from the C objects of Mlx5MrInterleaved list and set the
    mr_interleaved_p to this array address. The mr_interleaved_p should be
    allocated with enough size for those objects.
    :param mr_interleaved_p: Pointer to array of mlx5dv_mr_interleaved.
    :param mr_interleaved_lst: List of Mlx5MrInterleaved.
    """
    num_interleaved = len(mr_interleaved_lst)
    cdef dv.mlx5dv_mr_interleaved *tmp
    for i in range(num_interleaved):
        tmp = &(<Mlx5MrInterleaved>mr_interleaved_lst[i]).mlx5dv_mr_interleaved
        memcpy(mr_interleaved_p, tmp, sizeof(dv.mlx5dv_mr_interleaved))
        mr_interleaved_p += 1


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

    def wr_raw_wqe(self, wqe):
        """
        Build a raw work request
        :param wqe: A Wqe object
        """
        cdef void *wqe_ptr = <void *> <uintptr_t> wqe.address
        dv.mlx5dv_wr_raw_wqe(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex), wqe_ptr)

    def wr_mr_interleaved(self, Mlx5Mkey mkey, access_flags, repeat_count,
                          mr_interleaved_lst):
        """
        Registers an interleaved memory layout by using an indirect mkey and
        some interleaved data.
        :param mkey: A Mlx5Mkey instance to reg this memory.
        :param access_flags: The mkey access flags.
        :param repeat_count: Number of times to repeat the interleaved layout.
        :param mr_interleaved_lst: List of Mlx5MrInterleaved.
        """
        num_interleaved = len(mr_interleaved_lst)
        cdef dv.mlx5dv_mr_interleaved *mr_interleaved_p = \
            <dv.mlx5dv_mr_interleaved*>calloc(1, num_interleaved * sizeof(dv.mlx5dv_mr_interleaved))
        if mr_interleaved_p == NULL:
            raise MemoryError('Failed to calloc mr interleaved buffers')
        copy_mr_interleaved_array(mr_interleaved_p, mr_interleaved_lst)
        dv.mlx5dv_wr_mr_interleaved(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                                    mkey.mlx5dv_mkey, access_flags, repeat_count,
                                    num_interleaved, mr_interleaved_p)
        free(mr_interleaved_p)

    def wr_mr_list(self, Mlx5Mkey mkey, access_flags, sge_list):
        """
        Registers a memory layout based on list of SGE.
        :param mkey: A Mlx5Mkey instance to reg this memory.
        :param access_flags: The mkey access flags.
        :param sge_list: List of SGE.
        """
        num_sges = len(sge_list)
        cdef v.ibv_sge *sge_p = <v.ibv_sge*>calloc(1, num_sges * sizeof(v.ibv_sge))
        if sge_p == NULL:
            raise MemoryError('Failed to calloc sge buffers')
        copy_sg_array(sge_p, sge_list, num_sges)
        dv.mlx5dv_wr_mr_list(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                             mkey.mlx5dv_mkey, access_flags, num_sges, sge_p)
        free(sge_p)

    def wr_mkey_configure(self, Mlx5Mkey mkey, num_setters, Mlx5MkeyConfAttr mkey_config):
        """
        Create a work request to configure an Mkey
        :param mkey: A Mlx5Mkey instance to configure.
        :param num_setters: The number of setters that must be called after
                            this function.
        :param attr: The Mkey configuration attributes.
        """
        dv.mlx5dv_wr_mkey_configure(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                                    mkey.mlx5dv_mkey, num_setters,
                                    &mkey_config.mlx5dv_mkey_conf_attr)

    def wr_set_mkey_access_flags(self, access_flags):
        """
        Set the memory protection attributes for an Mkey
        :param access_flags: The mkey access flags.
        """
        dv.mlx5dv_wr_set_mkey_access_flags(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                                           access_flags)

    def wr_set_mkey_layout_list(self, sge_list):
        """
        Set a memory layout for an Mkey based on SGE list.
        :param sge_list: List of SGE.
        """
        num_sges = len(sge_list)
        cdef v.ibv_sge *sge_p = <v.ibv_sge*>calloc(1, num_sges * sizeof(v.ibv_sge))
        if sge_p == NULL:
            raise MemoryError('Failed to calloc sge buffers')
        copy_sg_array(sge_p, sge_list, num_sges)
        dv.mlx5dv_wr_set_mkey_layout_list(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                                          num_sges, sge_p)
        free(sge_p)

    def wr_set_mkey_layout_interleaved(self, repeat_count, mr_interleaved_lst):
        """
        Set an interleaved memory layout for an Mkey
        :param repeat_count: Number of times to repeat the interleaved layout.
        :param mr_interleaved_lst: List of Mlx5MrInterleaved.
        """
        num_interleaved = len(mr_interleaved_lst)
        cdef dv.mlx5dv_mr_interleaved *mr_interleaved_p = \
            <dv.mlx5dv_mr_interleaved*>calloc(1, num_interleaved * sizeof(dv.mlx5dv_mr_interleaved))
        if mr_interleaved_p == NULL:
            raise MemoryError('Failed to calloc mr interleaved buffers')
        copy_mr_interleaved_array(mr_interleaved_p, mr_interleaved_lst)
        dv.mlx5dv_wr_set_mkey_layout_interleaved(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                                                 repeat_count, num_interleaved,
                                                 mr_interleaved_p)
        free(mr_interleaved_p)

    def wr_set_mkey_crypto(self, Mlx5CryptoAttr attr):
        """
        Configure a MKey for crypto operation.
        :param attr: crypto attributes to set for the mkey.
        """
        dv.mlx5dv_wr_set_mkey_crypto(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                                     &attr.mlx5dv_crypto_attr)

    def wr_set_mkey_sig_block(self, Mlx5SigBlockAttr block_attr):
        """
        Configure a MKEY for block signature (data integrity) operation.
        :param block_attr: Block signature attributes to set for the mkey.
        """
        dv.mlx5dv_wr_set_mkey_sig_block(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                                        &block_attr.mlx5dv_sig_block_attr)

    def wr_memcpy(self, dest_lkey, dest_addr, src_lkey, src_addr, length):
        """
        Copies memory data on PCI bus using DMA functionality of the device.
        :param dest_lkey: Local key of the mkey to copy data to
        :param dest_addr: Memory address to copy data to
        :param src_lkey: Local key of the mkey to copy data from
        :param src_addr: Memory address to copy data from
        :param length: Length of data to be copied
        """
        dv.mlx5dv_wr_memcpy(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                            dest_lkey, dest_addr, src_lkey, src_addr, length)

    def cancel_posted_send_wrs(self, wr_id):
        """
        Cancel all pending send work requests with supplied wr_id in a QP in
        SQD state.
        :param wr_id: The WRID to cancel.
        :return: Number of work requests that were canceled.
        """
        rc = dv.mlx5dv_qp_cancel_posted_send_wrs(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                                                 wr_id)
        if rc < 0:
            raise PyverbsRDMAError(f'Failed to cancel send WRs', -rc)
        return rc

    def wr_set_dc_addr_stream(self, AH ah, remote_dctn, remote_dc_key, stream_id):
        """
        Attach a DC info to the last work request.
        :param ah: Address Handle to the requested DCT.
        :param remote_dctn: The remote DCT number.
        :param remote_dc_key: The remote DC key.
        :param stream_id: DCI stream channel_id
        """
        dv.mlx5dv_wr_set_dc_addr_stream(dv.mlx5dv_qp_ex_from_ibv_qp_ex(self.qp_ex),
                                        ah.ah, remote_dctn, remote_dc_key,
                                        stream_id)

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

    @staticmethod
    def map_ah_to_qp(AH ah, qp_num):
        """
        Map the destination path information in ah to the information extracted
        from the qp.
        :param ah: The target’s address handle.
        :param qp_num: The traffic initiator QP number.
        """
        rc = dv.mlx5dv_map_ah_to_qp(ah.ah, qp_num)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to map AH to QP #{qp_num}', rc)

    @staticmethod
    def modify_dci_stream_channel_id(QP qp, uint16_t stream_id):
        """
        Reset an errored stream_id in the HW DCI context.
        :param qp: A DCI QP in RTS state.
        :param stream_id: The desired stream_id that need to be reset.
        """
        rc = dv.mlx5dv_dci_stream_id_reset(qp.qp, stream_id)
        if rc != 0:
            raise PyverbsRDMAError(f'Failed to reset stream_id #{stream_id} for DCI QP'
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
         dve.MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS: 'Send ops flags',
         dve.MLX5DV_QP_INIT_ATTR_MASK_DCI_STREAMS: 'DCI Stream'}
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
             'Packet based credit mode',
         dve.MLX5DV_QP_CREATE_SIG_PIPELINING: 'Support signature pipeline support'}
    return bitmask_to_str(flags, l)


def send_ops_flags_to_str(flags):
    l = {dve.MLX5DV_QP_EX_WITH_MR_INTERLEAVED: 'With MR interleaved',
         dve.MLX5DV_QP_EX_WITH_MR_LIST: 'With MR list',
         dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE: 'With Mkey configure'}
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


cdef class WqeSeg(PyverbsCM):
    """
    An abstract class for WQE segments.
    Each WQE segment (such as control segment, data segment, etc.) should
    inherit from this class.
    """

    @staticmethod
    def sizeof():
        return 0

    cpdef _copy_to_buffer(self, addr):
        memcpy(<void *><uintptr_t>addr, <void *>self.segment, self.sizeof())

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.segment != NULL:
            free(self.segment)
            self.segment = NULL


cdef class WqeCtrlSeg(WqeSeg):
    """
    Wrapper class for dv.mlx5_wqe_ctrl_seg
    """

    def __init__(self, pi=0, opcode=0, opmod=0, qp_num=0, fm_ce_se=0, ds=0,
                 signature=0, imm=0):
        """
        Create a WqeCtrlSeg by creating a mlx5_wqe_ctrl_seg and
        using mlx5dv_set_ctrl_seg, segment values are accessed
        through the getters/setters.
        """
        self.segment = calloc(sizeof(dv.mlx5_wqe_ctrl_seg), 1)
        self.set_ctrl_seg(pi, opcode, opmod, qp_num, fm_ce_se, ds, signature, imm)

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('opcode',
                                   (<dv.mlx5_wqe_ctrl_seg *>self.segment).opmod_idx_opcode) + \
               print_format.format('qpn_ds',
                                   (<dv.mlx5_wqe_ctrl_seg *>self.segment).qpn_ds) + \
               print_format.format('signature',
                                   (<dv.mlx5_wqe_ctrl_seg *>self.segment).signature) + \
               print_format.format('fm_ce_se',
                                   (<dv.mlx5_wqe_ctrl_seg *>self.segment).fm_ce_se) + \
               print_format.format('imm',
                                   (<dv.mlx5_wqe_ctrl_seg *>self.segment).imm)

    def set_ctrl_seg(self, pi, opcode, opmod, qp_num, fm_ce_se, ds, signature, imm):
        dv.mlx5dv_set_ctrl_seg(<dv.mlx5_wqe_ctrl_seg *>self.segment, pi, opcode,
                               opmod, qp_num, fm_ce_se, ds, signature, imm)

    @staticmethod
    def sizeof():
        return sizeof(dv.mlx5_wqe_ctrl_seg)

    @property
    def addr(self):
        return <uintptr_t>self.segment

    @property
    def opmod_idx_opcode(self):
        return be32toh((<dv.mlx5_wqe_ctrl_seg *>self.segment).opmod_idx_opcode)
    @opmod_idx_opcode.setter
    def opmod_idx_opcode(self, val):
        (<dv.mlx5_wqe_ctrl_seg *>self.segment).opmod_idx_opcode = htobe32(val)

    @property
    def qpn_ds(self):
        return be32toh((<dv.mlx5_wqe_ctrl_seg *>self.segment).qpn_ds)
    @qpn_ds.setter
    def qpn_ds(self, val):
        (<dv.mlx5_wqe_ctrl_seg *>self.segment).qpn_ds = htobe32(val)

    @property
    def signature(self):
        return (<dv.mlx5_wqe_ctrl_seg *>self.segment).signature
    @signature.setter
    def signature(self, val):
        (<dv.mlx5_wqe_ctrl_seg *>self.segment).signature = val

    @property
    def fm_ce_se(self):
        return (<dv.mlx5_wqe_ctrl_seg *>self.segment).fm_ce_se
    @fm_ce_se.setter
    def fm_ce_se(self, val):
        (<dv.mlx5_wqe_ctrl_seg *>self.segment).fm_ce_se = val

    @property
    def imm(self):
        return be32toh((<dv.mlx5_wqe_ctrl_seg *>self.segment).imm)
    @imm.setter
    def imm(self, val):
        (<dv.mlx5_wqe_ctrl_seg *>self.segment).imm = htobe32(val)


cdef class WqeDataSeg(WqeSeg):

    def __init__(self, length=0, lkey=0, addr=0):
        """
        Create a dv.mlx5_wqe_data_seg by allocating it and using
        dv.mlx5dv_set_data_seg with the values received in init
        """
        self.segment = calloc(sizeof(dv.mlx5_wqe_data_seg), 1)
        self.set_data_seg(length, lkey, addr)

    @staticmethod
    def sizeof():
        return sizeof(dv.mlx5_wqe_data_seg)

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('byte_count',
                                   (<dv.mlx5_wqe_data_seg *>self.segment).byte_count) + \
               print_format.format('lkey', (<dv.mlx5_wqe_data_seg *>self.segment).lkey) + \
               print_format.format('addr', (<dv.mlx5_wqe_data_seg *>self.segment).addr)

    def set_data_seg(self, length, lkey, addr):
        dv.mlx5dv_set_data_seg(<dv.mlx5_wqe_data_seg *>self.segment,
                               length, lkey, addr)

    @property
    def byte_count(self):
        return be32toh((<dv.mlx5_wqe_data_seg *>self.segment).byte_count)
    @byte_count.setter
    def byte_count(self, val):
        (<dv.mlx5_wqe_data_seg *>self.segment).byte_count = htobe32(val)

    @property
    def lkey(self):
        return be32toh((<dv.mlx5_wqe_data_seg *>self.segment).lkey)
    @lkey.setter
    def lkey(self, val):
        (<dv.mlx5_wqe_data_seg *>self.segment).lkey = htobe32(val)

    @property
    def addr(self):
        return be64toh((<dv.mlx5_wqe_data_seg *>self.segment).addr)
    @addr.setter
    def addr(self, val):
        (<dv.mlx5_wqe_data_seg *>self.segment).addr = htobe64(val)


cdef class Wqe(PyverbsCM):
    """
    The Wqe class represents a WQE, which is one or more chained WQE segments.
    """

    def __init__(self, segments, addr=0):
        """
        Create a Wqe with <segments>, in case an address <addr> was not passed
        by the user, memory would be allocated according to the size needed and
        the segments are copied over to the buffer.
        :param segments: The segments (ctrl, data) of the Wqe
        :param addr: User address to write the WQE on (Optional)
        """
        self.segments = segments
        if addr:
            self.is_user_addr = True
            self.addr = <void*><uintptr_t> addr
        else:
            self.is_user_addr = False
            allocation_size = sum(map(lambda x: x.sizeof(), self.segments))
            self.addr = calloc(allocation_size, 1)
        addr = <uintptr_t>self.addr
        for seg in self.segments:
            seg._copy_to_buffer(addr)
            addr += seg.sizeof()

    @property
    def address(self):
        return <uintptr_t>self.addr

    def __str__(self):
        ret_str = ''
        i = 0
        for segment in self.segments:
            ret_str += f'Segment type {type(segment)} #{i}:\n' + str(segment)
            i += 1
        return ret_str

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.addr != NULL:
            if not self.is_user_addr:
                free(self.addr)
            self.addr = NULL


cdef class Mlx5UMEM(PyverbsCM):
    def __init__(self, Context context not None, size, addr=None, alignment=64,
                 access=0, pgsz_bitmap=0, comp_mask=0):
        """
        User memory object to be used by the DevX interface.
        If pgsz_bitmap or comp_mask were passed, the extended umem registration
        will be used.
        :param context: RDMA device context to create the action on
        :param size: The size of the addr buffer (or the internal buffer to be
                     allocated if addr is None)
        :param alignment: The alignment of the internally allocated buffer
                          (Valid if addr is None)
        :param addr: The memory start address to register (if None, the address
                     will be allocated internally)
        :param access: The desired memory protection attributes (default: 0)
        :param pgsz_bitmap: Represents the required page sizes
        :param comp_mask: Compatibility mask
        """
        super().__init__()
        cdef dv.mlx5dv_devx_umem_in umem_in

        if addr is not None:
            self.addr = <void*><uintptr_t>addr
            self.is_user_addr = True
        else:
            self.addr = <void*><uintptr_t>posix_memalign(size, alignment)
            memset(self.addr, 0, size)
            self.is_user_addr = False

        if pgsz_bitmap or comp_mask:
            umem_in.addr = self.addr
            umem_in.size = size
            umem_in.access = access
            umem_in.pgsz_bitmap = pgsz_bitmap
            umem_in.comp_mask = comp_mask
            self.umem = dv.mlx5dv_devx_umem_reg_ex(context.context, &umem_in)
        else:
            self.umem = dv.mlx5dv_devx_umem_reg(context.context, self.addr,
                                                size, access)
        if self.umem == NULL:
            raise PyverbsRDMAErrno("Failed to register a UMEM.")
        self.context = context
        self.context.add_ref(self)

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.umem != NULL:
            self.logger.debug('Closing Mlx5UMEM')
            rc = dv.mlx5dv_devx_umem_dereg(self.umem)
            try:
                if rc:
                    raise PyverbsError("Failed to dereg UMEM.", rc)
            finally:
                if not self.is_user_addr:
                    free(self.addr)
            self.umem = NULL
            self.context = None

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return print_format.format('umem id', self.umem_id) + \
               print_format.format('reg addr', self.umem_addr)

    @property
    def umem_id(self):
        return self.umem.umem_id

    @property
    def umem_addr(self):
        if self.addr:
            return <uintptr_t><void*>self.addr


cdef class Mlx5Cqe64(PyverbsObject):
    def __init__(self, addr):
        self.cqe = <dv.mlx5_cqe64*><uintptr_t> addr

    def dump(self):
        dump_format = '{:08x} {:08x} {:08x} {:08x}\n'
        str = ''
        for i in range(0, 16, 4):
            str += dump_format.format(be32toh((<uint32_t*>self.cqe)[i]),
                                      be32toh((<uint32_t*>self.cqe)[i + 1]),
                                      be32toh((<uint32_t*>self.cqe)[i + 2]),
                                      be32toh((<uint32_t*>self.cqe)[i + 3]))
        return str

    def is_empty(self):
        for i in range(16):
            if be32toh((<uint32_t*>self.cqe)[i]) != 0:
                return False
        return True

    @property
    def owner(self):
        return dv.mlx5dv_get_cqe_owner(self.cqe)
    @owner.setter
    def owner(self, val):
        dv.mlx5dv_set_cqe_owner(self.cqe, <uint8_t> val)

    @property
    def se(self):
        return dv.mlx5dv_get_cqe_se(self.cqe)

    @property
    def format(self):
        return dv.mlx5dv_get_cqe_format(self.cqe)

    @property
    def opcode(self):
        return dv.mlx5dv_get_cqe_opcode(self.cqe)

    @property
    def imm_inval_pkey(self):
        return be32toh(self.cqe.imm_inval_pkey)

    @property
    def wqe_id(self):
        return be16toh(self.cqe.wqe_id)

    @property
    def byte_cnt(self):
        return be32toh(self.cqe.byte_cnt)

    @property
    def timestamp(self):
        return be64toh(self.cqe.timestamp)

    @property
    def wqe_counter(self):
        return be16toh(self.cqe.wqe_counter)

    @property
    def signature(self):
        return self.cqe.signature

    @property
    def op_own(self):
        return self.cqe.op_own

    def __str__(self):
        return (<dv.mlx5_cqe64>((<dv.mlx5_cqe64*>self.cqe)[0])).__str__()
