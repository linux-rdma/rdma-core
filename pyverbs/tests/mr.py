# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019, Mellanox Technologies. All rights reserved.  See COPYING file
"""
Test module for pyverbs' mr module.
"""
import unittest
import random

from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsError
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.mr import MR, MW, DMMR
import pyverbs.tests.utils as u
import pyverbs.device as d
from pyverbs.pd import PD
import pyverbs.enums as e

MAX_IO_LEN = 1048576


class MRTest(unittest.TestCase):
    """
    Test various functionalities of the MR class.
    """
    @staticmethod
    def test_reg_mr():
        """ Test ibv_reg_mr() """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    with MR(pd, u.get_mr_length(), u.get_access_flags()) as mr:
                        pass

    @staticmethod
    def test_dereg_mr():
        """ Test ibv_dereg_mr() """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    with MR(pd, u.get_mr_length(), u.get_access_flags()) as mr:
                        mr.close()

    @staticmethod
    def test_reg_mr_bad_flow():
        """ Verify that trying to register a MR with None PD fails """
        try:
            MR(None, random.randint(0, 10000), u.get_access_flags())
        except TypeError as te:
            assert 'expected pyverbs.pd.PD' in te.args[0]
            assert 'got NoneType' in te.args[0]
        else:
            raise PyverbsRDMAErrno('Created a MR with None PD')

    @staticmethod
    def test_dereg_mr_twice():
        """ Verify that explicit call to MR's close() doesn't fails """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    with MR(pd, u.get_mr_length(), u.get_access_flags()) as mr:
                        # Pyverbs supports multiple destruction of objects,
                        # we are not expecting an exception here.
                        mr.close()
                        mr.close()

    @staticmethod
    def test_reg_mr_bad_flags():
        """ Verify that illegal flags combination fails as expected """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    flags = random.sample([e.IBV_ACCESS_REMOTE_WRITE,
                                           e.IBV_ACCESS_REMOTE_ATOMIC],
                                          random.randint(1, 2))
                    mr_flags = 0
                    for i in flags:
                        mr_flags += i.value
                    try:
                        MR(pd, u.get_mr_length(), mr_flags)
                    except PyverbsRDMAError as err:
                        assert 'Failed to register a MR' in err.args[0]
                    else:
                        raise PyverbsRDMAError('Registered a MR with illegal falgs')

    @staticmethod
    def test_write():
        """
        Test writing to MR's buffer
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    mr_len = u.get_mr_length()
                    with MR(pd, mr_len, u.get_access_flags()) as mr:
                        write_len = min(random.randint(1, MAX_IO_LEN), mr_len)
                        mr.write(u.get_data(write_len), write_len)

    @staticmethod
    def test_read():
        """
        Test reading from MR's buffer
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    mr_len = u.get_mr_length()
                    with MR(pd, mr_len, u.get_access_flags()) as mr:
                        write_len = min(random.randint(1, MAX_IO_LEN), mr_len)
                        write_str = u.get_data(write_len)
                        mr.write(write_str, write_len)
                        read_len = random.randint(1, write_len)
                        offset = random.randint(0, write_len-read_len)
                        read_str = mr.read(read_len, offset).decode()
                        assert read_str in write_str

    @staticmethod
    def test_lkey():
        """
        Test reading lkey property
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    length = u.get_mr_length()
                    with MR(pd, length, u.get_access_flags()) as mr:
                        mr.lkey

    @staticmethod
    def test_rkey():
        """
        Test reading rkey property
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    length = u.get_mr_length()
                    with MR(pd, length, u.get_access_flags()) as mr:
                        mr.rkey

    @staticmethod
    def test_buffer():
        """
        Test reading buf property
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    length = u.get_mr_length()
                    with MR(pd, length, u.get_access_flags()) as mr:
                        mr.buf


class MWTest(unittest.TestCase):
    """
    Test various functionalities of the MW class.
    """
    @staticmethod
    def test_reg_mw():
        """ Test ibv_alloc_mw() """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    with MW(pd, random.choice([e.IBV_MW_TYPE_1,
                                               e.IBV_MW_TYPE_2])):
                        pass

    @staticmethod
    def test_dereg_mw():
        """ Test ibv_dealloc_mw() """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    with MW(pd, random.choice([e.IBV_MW_TYPE_1,
                                               e.IBV_MW_TYPE_2])) as mw:
                        mw.close()

    @staticmethod
    def test_reg_mw_wrong_type():
        """ Test ibv_alloc_mw() """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                with PD(ctx) as pd:
                    try:
                        mw_type = random.randint(3, 100)
                        MW(pd, mw_type)
                    except PyverbsRDMAError:
                        pass
                    else:
                        raise PyverbsError('Created a MW with type {t}'.\
                                           format(t=mw_type))


class DMMRTest(unittest.TestCase):
    """
    Test various functionalities of the DMMR class.
    """
    @staticmethod
    def test_create_dm_mr():
        """
        Test ibv_reg_dm_mr
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device_ex()
                if attr.max_dm_size == 0:
                    return
                with PD(ctx) as pd:
                    dm_len = random.randrange(u.MIN_DM_SIZE, attr.max_dm_size,
                                              u.DM_ALIGNMENT)
                    dm_attrs = u.get_dm_attrs(dm_len)
                    with d.DM(ctx, dm_attrs) as dm:
                        dm_mr_len = random.randint(1, dm_len)
                        dm_mr_offset = random.randint(0, (dm_len - dm_mr_len))
                        DMMR(pd, dm_mr_len, e.IBV_ACCESS_ZERO_BASED, dm=dm,
                             offset=dm_mr_offset)

    @staticmethod
    def test_destroy_dm_mr():
        """
        Test freeing of dm_mr
        """
        lst = d.get_device_list()
        for dev in lst:
            with d.Context(name=dev.name.decode()) as ctx:
                attr = ctx.query_device_ex()
                if attr.max_dm_size == 0:
                    return
                with PD(ctx) as pd:
                    dm_len = random.randrange(u.MIN_DM_SIZE, attr.max_dm_size,
                                              u.DM_ALIGNMENT)
                    dm_attrs = u.get_dm_attrs(dm_len)
                    with d.DM(ctx, dm_attrs) as dm:
                        dm_mr_len = random.randint(1, dm_len)
                        dm_mr_offset = random.randint(0, (dm_len - dm_mr_len))
                        dm_mr = DMMR(pd, dm_mr_len, e.IBV_ACCESS_ZERO_BASED,
                                     dm=dm, offset=dm_mr_offset)
                        dm_mr.close()
