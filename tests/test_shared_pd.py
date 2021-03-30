# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Mellanox Technologies, Inc. All rights reserved. See COPYING file
"""
Test module for Shared PD.
"""
import unittest
import errno
import os

from tests.test_qpex import QpExRCRDMAWrite
from tests.base import RDMATestCase
from pyverbs.device import Context
from pyverbs.pd import PD
from pyverbs.mr import MR
import pyverbs.enums as e
import tests.utils as u


def get_import_res_class(base_class):
    """
    This function creates a class that inherits base_class of any BaseResources
    type. Its purpose is to behave exactly as base_class does, except for the
    objects creation, which instead of creating context, PD and MR, it imports
    them. Hence the returned class must be initialized with (cmd_fd, pd_handle,
    mr_handle, mr_addr, **kwargs), while kwargs are the arguments needed
    (if any) for base_class. In addition it has unimport_resources() method
    which unimprot all the resources and closes the imported PD object.
    :param base_class: The base resources class to inherit from
    :return: ImportResources(cmd_fd, pd_handle, mr_handle, mr_addr, **kwargs)
             class
    """
    class ImportResources(base_class):
        def __init__(self, cmd_fd, pd_handle, mr_handle, mr_addr=None, **kwargs):
            self.cmd_fd = cmd_fd
            self.pd_handle = pd_handle
            self.mr_handle = mr_handle
            self.mr_addr = mr_addr
            super(ImportResources, self).__init__(**kwargs)

        def create_context(self):
            try:
                self.ctx = Context(cmd_fd=self.cmd_fd)
            except u.PyverbsRDMAError as ex:
                if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                    raise unittest.SkipTest('Importing a device is not supported')
                raise ex

        def create_pd(self):
            self.pd = PD(self.ctx, handle=self.pd_handle)

        def create_mr(self):
            self.mr = MR(self.pd, handle=self.mr_handle, address=self.mr_addr)

        def unimport_resources(self):
            self.mr.unimport()
            self.pd.unimport()
            self.pd.close()

    return ImportResources


class SharedPDTestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.server_res = None
        self.imported_res = []

    def tearDown(self):
        for res in self.imported_res:
            res.unimport_resources()
        super().tearDown()

    def test_imported_rc_ex_rdma_write(self):
        setup_params = {'dev_name': self.dev_name, 'ib_port': self.ib_port,
                        'gid_index': self.gid_index}
        self.server_res = QpExRCRDMAWrite(**setup_params)
        cmd_fd_dup = os.dup(self.server_res.ctx.cmd_fd)
        import_cls = get_import_res_class(QpExRCRDMAWrite)
        server_import = import_cls(
            cmd_fd_dup, self.server_res.pd.handle, self.server_res.mr.handle,
            # The imported MR's address is NULL, so using the address of the
            # "main" MR object to be able to validate the message
            self.server_res.mr.buf,
            **setup_params)
        self.imported_res.append(server_import)
        client = QpExRCRDMAWrite(**setup_params)
        client.pre_run(server_import.psns, server_import.qps_num)
        server_import.pre_run(client.psns, client.qps_num)
        client.rkey = server_import.mr.rkey
        server_import.rkey = client.mr.rkey
        client.raddr = server_import.mr.buf
        server_import.raddr = client.mr.buf
        u.rdma_traffic(client, server_import, self.iters, self.gid_index,
                       self.ib_port, send_op=e.IBV_QP_EX_WITH_RDMA_WRITE, new_send=True)
