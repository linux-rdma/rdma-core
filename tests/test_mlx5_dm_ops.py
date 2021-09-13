# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 NVIDIA Corporation . All rights reserved. See COPYING file

from threading import Thread
from queue import Queue
import unittest
import struct
import errno

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, \
    Mlx5DmOpAddr
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
from tests.mlx5_base import Mlx5PyverbsAPITestCase
import pyverbs.providers.mlx5.mlx5_enums as dve
import pyverbs.device as d


MEMIC_ATOMIC_INCREMENT = 0x0
MEMIC_ATOMIC_TEST_AND_SET = 0x1

MLX5_CMD_OP_QUERY_HCA_CAP = 0x100
MLX5_CMD_MOD_DEVICE_MEMORY_CAP = 0xF
MLX5_CMD_OP_QUERY_HCA_CAP_OUT_LEN = 0x1010


def requires_memic_atomic_support(func):
    def wrapper(instance):
        cmd_in = struct.pack('!HIH8s', MLX5_CMD_OP_QUERY_HCA_CAP, 0,
                             MLX5_CMD_MOD_DEVICE_MEMORY_CAP << 1 | 0x1,
                             bytes(8))
        cmd_out = Mlx5Context.devx_general_cmd(instance.ctx, cmd_in,
                                               MLX5_CMD_OP_QUERY_HCA_CAP_OUT_LEN)
        cmd_view = memoryview(cmd_out)
        status = cmd_view[0]
        if status:
            raise PyverbsRDMAError('Query Device Memory CAPs failed with status'
                                   f' ({status})')

        memic_op_support = int.from_bytes(cmd_view[80:84], 'big')
        increment_size_sup = cmd_view[20]
        test_and_set_size_sup = cmd_view[22]
        # Verify that MEMIC atomic operations (both increment and test_and_set)
        # are supported with write/read size of 1 Byte.
        if memic_op_support & 0x3 != 0x3:
            raise unittest.SkipTest('MEMIC atomic operations are not supported')
        if not increment_size_sup & test_and_set_size_sup & 0x1:
            raise unittest.SkipTest(
                'MEMIC atomic operations are not supported with 1 Bytes read/write sizes')
        return func(instance)
    return wrapper


class Mlx5DmOpAddresses(Mlx5PyverbsAPITestCase):
    def setUp(self):
        super().setUp()
        self.dm_size = int(self.attr_ex.max_dm_size / 2)

    def create_context(self):
        try:
            attr = Mlx5DVContextAttr(dve.MLX5DV_CONTEXT_FLAGS_DEVX)
            self.ctx = Mlx5Context(attr, self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 DevX context is not supported')

    def _write_to_op_addr(self):
        try:
            inc_addr = Mlx5DmOpAddr(self.dm, MEMIC_ATOMIC_INCREMENT)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                self.skip_queue.put(unittest.SkipTest(
                    'MEMIC_ATOMIC_INCREMENT op is not supported'))
                return
            raise ex
        inc_addr.write(b'\x01')
        inc_addr.unmap(self.dm_size)

    def _read_from_op_addr(self):
        try:
            test_and_set_addr = Mlx5DmOpAddr(self.dm, MEMIC_ATOMIC_TEST_AND_SET)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                self.skip_queue.put(unittest.SkipTest(
                    'MEMIC_ATOMIC_TEST_AND_SET op is not supported'))
                return
            raise ex
        val = test_and_set_addr.read(1)
        test_and_set_addr.unmap(self.dm_size)
        return val

    @requires_memic_atomic_support
    def test_dm_atomic_ops(self):
        """
        Tests "increment" and "test_and_set" MEMIC atomic operations.
        The test does two increments to the same buffer data and verifies the
        values using test_and_set.
        Then verifies that the latter op sets the buffer as expected.
        """
        with d.DM(self.ctx, d.AllocDmAttr(length=self.dm_size)) as dm:
            # Set DM buffer to 0
            dm.copy_to_dm(0, bytes(self.dm_size), self.dm_size)
            try:
                inc_addr = Mlx5DmOpAddr(dm, MEMIC_ATOMIC_INCREMENT)
                test_and_set_addr = Mlx5DmOpAddr(dm, MEMIC_ATOMIC_TEST_AND_SET)
            except PyverbsRDMAError as ex:
                if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                    raise unittest.SkipTest('MEMIC atomic operations are not supported')
                raise ex
            inc_addr.write(b'\x01')
            inc_addr.write(b'\x01')
            # Now we should read 0x02 and the memory set to ffs
            val = int.from_bytes(test_and_set_addr.read(1), 'big')
            self.assertEqual(val, 2)
            # Verify that TEST_AND_SET set the memory to ffs
            val = int.from_bytes(test_and_set_addr.read(1), 'big')
            self.assertEqual(val, 255)
            inc_addr.unmap(self.dm_size)
            test_and_set_addr.unmap(self.dm_size)

    @requires_memic_atomic_support
    def test_parallel_dm_atomic_ops(self):
        """
        Runs multiple threads that do test_and_set operation, followed by
        multiple threads that do increments of +1, to the same DM buffer.
        Then verifies that the buffer data was incremented as expected.
        """
        threads = []
        num_threads = 10
        self.skip_queue = Queue()
        with d.DM(self.ctx, d.AllocDmAttr(length=self.dm_size)) as self.dm:
            for _ in range(num_threads):
                threads.append(Thread(target=self._read_from_op_addr))
                threads[-1].start()
            for thread in threads:
                thread.join()

            threads = []
            for _ in range(num_threads):
                threads.append(Thread(target=self._write_to_op_addr))
                threads[-1].start()
            for thread in threads:
                thread.join()

            if not self.skip_queue.empty():
                raise self.skip_queue.get()

            val = int.from_bytes(self._read_from_op_addr(), 'big')
            self.assertEqual(val, num_threads - 1,
                             f'Read value is ({val}) is different than expected ({num_threads-1})' )
