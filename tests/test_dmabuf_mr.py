# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
# Copyright (c) 2020 Intel Corporation. All rights reserved. See COPYING file
# Copyright 2023 Amazon.com, Inc. or its affiliates. All rights reserved.
"""
Test module for pyverbs' dma-buf mr module.
"""
import unittest
import random
import errno

from tests.base import PyverbsAPITestCase, RCResources, RDMATestCase
from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.mr import DmaBufMR
from pyverbs.dmabuf import DmaBuf, DrmDmaBuf, HabanaLabsDmaBuf, GpuType
from pyverbs.qp import QPAttr
import pyverbs.device as d
from pyverbs.pd import PD
import pyverbs.enums as e
import tests.utils as u

MAX_IO_LEN = 1048576


class DmaBufFactory:
    def __init__(self, gpu_type: GpuType, drm_gpu=0, drm_gtt=0):
        gpu_class = {GpuType.drm:DrmDmaBuf, GpuType.habana:HabanaLabsDmaBuf}
        self.gpu_type = gpu_type
        self.drm_gpu = drm_gpu
        self.drm_gtt = drm_gtt
        self.dmabuf_type = gpu_class[gpu_type]

    def get_dmabuf(self, size):
        if self.gpu_type == GpuType.drm:
            return DrmDmaBuf(size, self.drm_gpu, self.drm_gtt)
        elif self.gpu_type == GpuType.habana:
            return HabanaLabsDmaBuf(size)
        raise Exception(f"Unexpected GPU type: {self.gpu_type}")


def check_drm_gpu_dmabuf(gpu=0):
    """
    Check if DRM gpu exists in the system.
    """
    device_num = 128 + gpu
    try:
        return DrmDmaBuf(1, gpu=gpu)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EACCES:
            raise unittest.SkipTest(f'Lack of permission to access /dev/dri/renderD{device_num}')
        return None


def check_habana_gpu_dmabuf():
    """
    Check if HabanaLabs gpu exists in the system.
    """
    try:
        return HabanaLabsDmaBuf(1)
    except Exception:
        return None


def check_dmabuf_support(drm_gpu=0):
    """
    Check if dma-buf allocation is supported by the system.
    Skip the test on failure.
    """
    dmabuf = check_drm_gpu_dmabuf(drm_gpu)
    if dmabuf:
        return dmabuf, GpuType.drm

    dmabuf = check_habana_gpu_dmabuf()
    if dmabuf:
        return dmabuf, GpuType.habana

    raise unittest.SkipTest(f'There is no gpu available for creating DMA buffer')


def check_dmabuf_mr_support(pd, dmabuf: DmaBuf):
    """
    Check if dma-buf MR registration is supported by the driver.
    Skip the test on failure.
    """
    try:
        DmaBufMR(pd, 1, 0, dmabuf)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EOPNOTSUPP:
            raise unittest.SkipTest('Reg dma-buf MR is not supported by the RDMA driver')


def get_dmabuf_factory(pd, drm_gpu=0, drm_gtt=0):
    """
    Check if dma-buf allocation is supported by the system and the driver.
    If so, return DmaBufFactory that creates the supported buf on request.
    Skip the tests on failure.
    """
    dmabuf, gpu_type = check_dmabuf_support(drm_gpu)
    check_dmabuf_mr_support(pd, dmabuf)
    return DmaBufFactory(gpu_type, drm_gpu, drm_gtt)


def create_dmabuf_mr(pd, len, flags, dmabuf, offset = 0):
    try:
        return DmaBufMR(pd, len, flags, dmabuf, offset)
    except PyverbsRDMAError as ex:
        if ex.error_code == errno.EOPNOTSUPP:
            return None
        raise


class DmaBufMRTest(PyverbsAPITestCase):
    """
    Test various functionalities of the DmaBufMR class.
    """
    def setUp(self):
        super().setUp()
        drm_gpu = self.config['gpu']
        drm_gtt = self.config['gtt']
        self.pd = PD(self.ctx)
        self.dmabuf_factory = get_dmabuf_factory(self.pd, drm_gpu, drm_gtt)

    def test_dmabuf_reg_mr(self):
        """
        Test ibv_reg_dmabuf_mr()
        """
        flags = u.get_dmabuf_access_flags(self.ctx)
        for f in flags:
            len = u.get_mr_length()
            for off in [0, len//2]:
                dmabuf = self.dmabuf_factory.get_dmabuf(len + off)
                create_dmabuf_mr(self.pd, len, f, dmabuf, off)

    def test_dmabuf_dereg_mr(self):
        """
        Test ibv_dereg_mr() with DmaBufMR
        """
        flags = u.get_dmabuf_access_flags(self.ctx)
        for f in flags:
            len = u.get_mr_length()
            for off in [0, len//2]:
                dmabuf = self.dmabuf_factory.get_dmabuf(len + off)
                mr = create_dmabuf_mr(self.pd, len, f, dmabuf, off)
                if not mr:
                    continue
                mr.close()

    def test_dmabuf_dereg_mr_twice(self):
        """
        Verify that explicit call to DmaBufMR's close() doesn't fail
        """
        flags = u.get_dmabuf_access_flags(self.ctx)
        for f in flags:
            len = u.get_mr_length()
            for off in [0, len//2]:
                dmabuf = self.dmabuf_factory.get_dmabuf(len + off)
                mr = create_dmabuf_mr(self.pd, len, f, dmabuf, off)
                if not mr:
                    continue
                # Pyverbs supports multiple destruction of objects,
                # we are not expecting an exception here.
                mr.close()
                mr.close()

    def test_dmabuf_reg_mr_bad_flags(self):
        """
        Verify that DmaBufMR with illegal flags combination fails as expected
        """
        for i in range(5):
            flags = random.sample([e.IBV_ACCESS_REMOTE_WRITE, e.IBV_ACCESS_REMOTE_ATOMIC],
                                   random.randint(1, 2))
            mr_flags = 0
            for i in flags:
                mr_flags += i.value
            try:
                len = u.get_mr_length()
                dmabuf = self.dmabuf_factory.get_dmabuf(len)
                DmaBufMR(self.pd, len, mr_flags, dmabuf)
            except PyverbsRDMAError as err:
                assert 'Failed to register a dma-buf MR' in err.args[0]
            else:
                raise PyverbsRDMAError('Registered a dma-buf MR with illegal falgs')

    def test_dmabuf_write(self):
        """
        Test writing to DmaBufMR's buffer
        """
        for i in range(10):
            mr_len = u.get_mr_length()
            flags = u.get_dmabuf_access_flags(self.ctx)
            for f in flags:
                for mr_off in [0, mr_len//2]:
                    dmabuf = self.dmabuf_factory.get_dmabuf(mr_len + mr_off)
                    mr = create_dmabuf_mr(self.pd, mr_len, f, dmabuf, mr_off)
                    if not mr:
                        continue
                    write_len = min(random.randint(1, MAX_IO_LEN), mr_len)
                    try:
                        mr.write('a' * write_len, write_len)
                    except PyverbsRDMAError as ex:
                        if ex.error_code == errno.EOPNOTSUPP:
                            raise unittest.SkipTest("DMA buffer write isn't supported")

    def test_dmabuf_read(self):
        """
        Test reading from DmaBufMR's buffer
        """
        for i in range(10):
            mr_len = u.get_mr_length()
            flags = u.get_dmabuf_access_flags(self.ctx)
            for f in flags:
                for mr_off in [0, mr_len//2]:
                    dmabuf = self.dmabuf_factory.get_dmabuf(mr_len + mr_off)
                    mr = create_dmabuf_mr(self.pd, mr_len, f, dmabuf, mr_off)
                    if not mr:
                        continue
                    write_len = min(random.randint(1, MAX_IO_LEN), mr_len)
                    write_str = 'a' * write_len
                    try:
                        mr.write(write_str, write_len)
                    except PyverbsRDMAError as ex:
                        if ex.error_code == errno.EOPNOTSUPP:
                            raise unittest.SkipTest("DMA buffer write isn't supported")
                    read_len = random.randint(1, write_len)
                    offset = random.randint(0, write_len-read_len)
                    try:
                        read_str = mr.read(read_len, offset).decode()
                    except PyverbsRDMAError as ex:
                        if ex.error_code == errno.EOPNOTSUPP:
                            raise unittest.SkipTest("DMA buffer read isn't supported")
                    assert read_str in write_str

    def test_dmabuf_lkey(self):
        """
        Test reading lkey property
        """
        length = u.get_mr_length()
        flags = u.get_dmabuf_access_flags(self.ctx)
        for f in flags:
            dmabuf = self.dmabuf_factory.get_dmabuf(length)
            mr = create_dmabuf_mr(self.pd, length, f, dmabuf)
            if not mr:
                continue
            mr.rkey

    def test_dmabuf_rkey(self):
        """
        Test reading rkey property
        """
        length = u.get_mr_length()
        flags = u.get_dmabuf_access_flags(self.ctx)
        for f in flags:
            dmabuf = self.dmabuf_factory.get_dmabuf(length)
            mr = create_dmabuf_mr(self.pd, length, f, dmabuf)
            if not mr:
                continue
            mr.rkey


class DmaBufRC(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, dmabuf_factory):
        """
        Initialize an DmaBufRC object.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param dmabuf_factory: Factory for creating dma buffers.
        :gtt: Allocate dmabuf from GTT instead og VRAM
        """
        self.dmabuf_factory = dmabuf_factory
        super(DmaBufRC, self).__init__(dev_name=dev_name, ib_port=ib_port,
                                       gid_index=gid_index)

    def create_mr(self):
        access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        dmabuf = self.dmabuf_factory.get_dmabuf(self.msg_size)
        mr = DmaBufMR(self.pd, self.msg_size, access, dmabuf)
        self.mr = mr

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        qp_access = e.IBV_ACCESS_LOCAL_WRITE | e.IBV_ACCESS_REMOTE_WRITE
        qp_attr.qp_access_flags = qp_access
        return qp_attr


class DmaBufTestCase(RDMATestCase):
    def setUp(self):
        super(DmaBufTestCase, self).setUp()
        self.iters = 100
        drm_gpu = self.config['gpu']
        drm_gtt = self.config['gtt']
        self.pd = PD(d.Context(name=self.dev_name))
        self.dmabuf_factory = get_dmabuf_factory(self.pd, drm_gpu, drm_gtt)

    def create_players(self, resource, **resource_arg):
        """
        Init dma-buf tests resources.
        :param resource: The RDMA resources to use. A class of type
                         BaseResources.
        :param resource_arg: Dict of args that specify the resource specific
                             attributes.
        :return: The (client, server) resources.
        """
        try:
            client = resource(**self.dev_info, **resource_arg)
            server = resource(**self.dev_info, **resource_arg)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create player with resource type is not supported')
            raise ex
        client.pre_run(server.psns, server.qps_num)
        server.pre_run(client.psns, client.qps_num)
        return client, server

    def test_dmabuf_rc_traffic(self):
        """
        Test send/recv using dma-buf MR over RC
        """
        client, server = self.create_players(DmaBufRC, dmabuf_factory=self.dmabuf_factory)
        u.traffic(client, server, self.iters, self.gid_index, self.ib_port)

    def test_dmabuf_rdma_traffic(self):
        """
        Test rdma write using dma-buf MR
        """
        client, server = self.create_players(DmaBufRC, dmabuf_factory=self.dmabuf_factory)
        server.rkey = client.mr.rkey
        server.raddr = client.mr.offset
        client.rkey = server.mr.rkey
        client.raddr = server.mr.offset
        u.rdma_traffic(client, server, self.iters, self.gid_index, self.ib_port,
                       send_op=e.IBV_WR_RDMA_WRITE)
