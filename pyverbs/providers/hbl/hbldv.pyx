# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright 2022-2024 HabanaLabs, Ltd.
# Copyright (C) 2023-2024, Intel Corporation.
# All Rights Reserved.

cimport pyverbs.providers.hbl.libhbl as dv

from cpython.mem cimport PyMem_Malloc, PyMem_Free
from libc.stdint cimport uint32_t, uint64_t
from posix.mman cimport munmap
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.pd cimport PD
from pyverbs.pyverbs_error import PyverbsUserError, PyverbsRDMAError, PyverbsError
from pyverbs.qp cimport QP, QPInitAttr, QPAttr


cdef class HblDVContextAttr(PyverbsObject):
    """
    Represent hbldv_ucontext_attr struct. This class is used to open an hbl
    device.
    """
    @property
    def ports_mask(self):
        return self.attr.ports_mask

    @ports_mask.setter
    def ports_mask(self,val):
        self.attr.ports_mask = val

    @property
    def core_fd(self):
        return self.attr.core_fd

    @core_fd.setter
    def core_fd(self,val):
        self.attr.core_fd = val

cdef class HblDVDeviceAttr(PyverbsObject):
    """
    Represents hbl device-specific capabilities reported by hbldv_query_device.
    """
    @property
    def caps(self):
        return self.attr.caps

    @property
    def ports_mask(self):
        return self.attr.ports_mask

cdef class HblContext(Context):
    """
    Represent hbl context, which extends Context.
    """
    def __init__(self, HblDVContextAttr attr not None, name=''):
        """
        Open an hbl device using the given attributes
        :param name: The RDMA device's name (used by parent class)
        :param attr: hbl-specific device attributes
        :return: None
        """
        super().__init__(name=name, attr=attr)
        if not dv.hbldv_is_supported(self.device):
            raise PyverbsUserError('This is not an hbl device')
        self.context = dv.hbldv_open_device(self.device, &attr.attr)
        if self.context == NULL:
            raise PyverbsRDMAErrno('Failed to open hbl context on {dev}'
                                   .format(dev=self.name))

    def query_hbl_device(self):
        """
        Query for device-specific attributes.
        :return: An HblDVDeviceAttr containing the attributes.
        """
        dv_attr = HblDVDeviceAttr()
        rc = dv.hbldv_query_device(self.context, &dv_attr.attr)
        if rc:
            raise PyverbsRDMAError(f'Failed to query hbl device {self.name}', rc)
        return dv_attr

    cpdef close(self):
        if self.context != NULL:
            super(HblContext, self).close()


cdef class HblDVPortExAttr(PyverbsObject):
    """
    Represent hbldv_port_ex_attr struct. This class is used to set port extended params.
    """
    @property
    def port_num(self):
        return self.attr.port_num

    @port_num.setter
    def port_num(self,val):
        self.attr.port_num = val

    @property
    def max_num_of_wqs(self):
        return self.attr.wq_arr_attr[0].max_num_of_wqs

    @max_num_of_wqs.setter
    def max_num_of_wqs(self, val):
        self.attr.wq_arr_attr[0].max_num_of_wqs = val

    @property
    def max_num_of_wqes_in_wq(self):
        return self.attr.wq_arr_attr[0].max_num_of_wqes_in_wq

    @max_num_of_wqes_in_wq.setter
    def max_num_of_wqes_in_wq(self, val):
        self.attr.wq_arr_attr[0].max_num_of_wqes_in_wq = val

    @property
    def mem_id(self):
        return self.attr.wq_arr_attr[0].mem_id

    @mem_id.setter
    def mem_id(self,val):
        self.attr.wq_arr_attr[0].mem_id = val

    @property
    def swq_granularity(self):
        return self.attr.wq_arr_attr[0].swq_granularity

    @swq_granularity.setter
    def swq_granularity(self,val):
        self.attr.wq_arr_attr[0].swq_granularity = val

    @property
    def caps(self):
        return self.attr.caps

    @caps.setter
    def caps(self,val):
        self.attr.caps = val


cdef class HblDVPortExAttrTmp(PyverbsObject):
    """
    Represent hbldv_port_ex_attr struct. This class is used to set port extended params.
    """
    @property
    def port_num(self):
        return self.attr.port_num

    @port_num.setter
    def port_num(self,val):
        self.attr.port_num = val

    @property
    def max_num_of_wqs(self):
        return self.attr.wq_arr_attr[0].max_num_of_wqs

    @max_num_of_wqs.setter
    def max_num_of_wqs(self, val):
        self.attr.wq_arr_attr[0].max_num_of_wqs = val

    @property
    def max_num_of_wqes_in_wq(self):
        return self.attr.wq_arr_attr[0].max_num_of_wqes_in_wq

    @max_num_of_wqes_in_wq.setter
    def max_num_of_wqes_in_wq(self, val):
        self.attr.wq_arr_attr[0].max_num_of_wqes_in_wq = val

    @property
    def mem_id(self):
        return self.attr.wq_arr_attr[0].mem_id

    @mem_id.setter
    def mem_id(self,val):
        self.attr.wq_arr_attr[0].mem_id = val

    @property
    def swq_granularity(self):
        return self.attr.wq_arr_attr[0].swq_granularity

    @swq_granularity.setter
    def swq_granularity(self,val):
        self.attr.wq_arr_attr[0].swq_granularity = val

    @property
    def caps(self):
        return self.attr.caps

    @caps.setter
    def caps(self,val):
        self.attr.caps = val

cdef class HblDVSetPortEx(PyverbsObject):
    """
    This class is used to set port extended params.
    """
    def set_port_ex(self, Context ctx not None, HblDVPortExAttr attr not None):
        rc = dv.hbldv_set_port_ex(ctx.context, &attr.attr)
        if rc != 0:
            raise PyverbsRDMAErrno("Failed to set port extended params")


cdef class HblDVUserFIFOAttr(PyverbsObject):
    """
    Represent hbldv_usr_fifo_attr struct. This class is used to set a user FIFO.
    """
    @property
    def port_num(self):
        return self.attr.port_num

    @port_num.setter
    def port_num(self,val):
        self.attr.port_num = val


cdef class HblDVUserFIFO(PyverbsObject):
    """
    Represent hbl user FIFO resource.
    """
    def create_usr_fifo(self, Context ctx not None, HblDVUserFIFOAttr attr not None):
        """
        Creates a user FIFO resource.
        :param ctx: The device context to issue the action on.
        :param attr: The attributes used to allocate this user FIFO.
        """
        if self.usr_fifo != NULL:
            raise PyverbsRDMAErrno("User FIFO already created")

        self.usr_fifo = dv.hbldv_create_usr_fifo(ctx.context, &attr.attr)
        if self.usr_fifo == NULL:
            raise PyverbsRDMAErrno("Failed to create a user FIFO")

    def destroy_usr_fifo(self):
        """
        Destroys a user FIFO resource.
        """
        if self.usr_fifo == NULL:
            raise PyverbsRDMAErrno("No user FIFO to destroy")
        err = dv.hbldv_destroy_usr_fifo(self.usr_fifo)
        if err:
            raise PyverbsRDMAError('Failed to destroy user FIFO', err)
        self.usr_fifo = NULL



cdef class HblDVCQattr(PyverbsObject):
    """
    Represent hbldv_cq_attr struct. This class is used to create a CQ.
    """
    @property
    def port_num(self):
        return self.cq_attr.port_num

    @port_num.setter
    def port_num(self,val):
        self.cq_attr.port_num = val

    @property
    def cq_type(self):
        return self.cq_attr.cq_type

    @cq_type.setter
    def cq_type(self,val):
        self.cq_attr.cq_type = val

cdef class HblDVCQ(PyverbsObject):
    """
    Represent CQ resource. This class is used to create and destroy CQs.
    """
    def create_cq(self, Context ctx, int cqes, HblDVCQattr cq_attr):
        self.ibvcq = dv.hbldv_create_cq(ctx.context, cqes, NULL, 0, &cq_attr.cq_attr)
        if self.ibvcq == NULL:
            raise PyverbsRDMAErrno("Failed to create a CQ")

    def query_cq(self, HblDVQueryCQ attr not None):
        err = dv.hbldv_query_cq(self.ibvcq, &attr.query_cq_attr)
        if err:
            raise PyverbsRDMAErrno("Failed to query CQ")

    def destroy_cq(self):
        v.ibv_destroy_cq(self.ibvcq)


cdef class HblDVPortAttr(PyverbsObject):
    """
    Represent hbldv_query_port_attr struct. This class is used to query port info.
    """
    @property
    def hbl_attr(self):
        return self


cdef class HblQueryPort(PyverbsObject):
    """
    Represent hbl port specific attributes.
    """
    def query_port(self, Context ctx not None, int port, HblDVPortAttr attr not None):
        """
        Creates a Query Port instance
        :param ctx: The device context to issue the action on.
        :param port_num: the port for which info is required.
        :param attr: The attributes used to get port info from.
        """
        rc = dv.hbldv_query_port(ctx.context, port, &attr.hbl_attr)
        if rc != 0:
            raise PyverbsRDMAErrno("query port returns error")

cdef class HblDVQueryQP(PyverbsObject):
    @property
    def qp_num(self):
        return self.query_qp_attr.qp_num

cdef class HblDVQP(PyverbsObject):
    """
    Represent HBL QP resource. This class is used to create, modify, destroy QP.
    """
    def create_qp(self, PD pd, QPInitAttr attr):
        self.ibvqp = v.ibv_create_qp(<v.ibv_pd*>pd.pd, &attr.attr)
        if self.ibvqp == NULL:
            raise PyverbsRDMAErrno("Failed to create a QP")

    def modify_qp(self, QPAttr qp_attr, int attr_mask, HblDVModifyQP attr):
        err = dv.hbldv_modify_qp(self.ibvqp, &qp_attr.attr, attr_mask, &attr.attr)
        if err:
            raise PyverbsRDMAErrno("Failed to Modify QP")

    def destroy_qp(self):
        err = v.ibv_destroy_qp(self.ibvqp)
        if err:
            raise PyverbsRDMAErrno("Failed to destroy QP")

    def query_qp(self, HblDVQueryQP attr not None):
        err = dv.hbldv_query_qp(self.ibvqp, &attr.query_qp_attr)
        if err:
            raise PyverbsRDMAErrno("Failed to query QP")

cdef class HblDVEncapAttr(PyverbsObject):
    """
    Represent hbldv_encap_attr struct. This class is used to create a Encap.
    """
    def __init__(self):
        hdr = <uint32_t *>PyMem_Malloc(32)
        if not hdr:
            raise MemoryError()
        hdr[0] = 0x8
        self.encap_attr.tnl_hdr_ptr = <uint64_t>hdr

    def __del__(self):
        PyMem_Free(<void *>self.encap_attr.tnl_hdr_ptr)

    @property
    def port_num(self):
        return self.encap_attr.port_num

    @port_num.setter
    def port_num(self,val):
        self.encap_attr.port_num = val

    @property
    def encap_type(self):
        return self.encap_attr.encap_type

    @encap_type.setter
    def encap_type(self,val):
        self.encap_attr.encap_type = val

    @property
    def tnl_hdr_size(self):
        return self.encap_attr.tnl_hdr_size

    @tnl_hdr_size.setter
    def tnl_hdr_size(self,val):
        self.encap_attr.tnl_hdr_size = val

cdef class HblDVEncap(PyverbsObject):
    """
    Represent Encap resource. This class is used to create and destroy Encaps.
    """
    def create_encap(self, Context ctx, HblDVEncapAttr encap_attr, HblDVEncapOut encap_out):
        self.hbldv_encap = dv.hbldv_create_encap(ctx.context, &encap_attr.encap_attr)
        if self.hbldv_encap == NULL:
            raise PyverbsRDMAErrno("Failed to create a Encap")

    def destroy_encap(self):
        dv.hbldv_destroy_encap(self.hbldv_encap)

cdef class HblDVModifyQP(PyverbsObject):
    """
    Represent hbldv_qp_attr struct. This class is used to modify a QP.
    """
    @property
    def wq_type(self):
        return self.attr.wq_type

    @wq_type.setter
    def wq_type(self,val):
        self.attr.wq_type = val
