# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2022 Nvidia Inc. All rights reserved. See COPYING file

"""
This module provides utilities and auxiliary functions for CUDA related tests
including the initialization/tear down needed and some error handlers.
"""

import unittest

try:
    from cuda import cuda, cudart, nvrtc
    CUDA_FOUND = True
except ImportError:
    CUDA_FOUND = False


def requires_cuda(func):
    def inner(instance):
        if not CUDA_FOUND:
            raise unittest.SkipTest(
                'cuda-python 12.0+ must be installed to run CUDA tests')
        res = cudart.cudaGetDeviceCount()
        if res[0].value == cuda.CUresult.CUDA_ERROR_NO_DEVICE or res[1] == 0:
            raise unittest.SkipTest('No CUDA-capable devices were detected')
        return func(instance)
    return inner


def _cuda_get_error_enum(error):
    if isinstance(error, cuda.CUresult):
        err, name = cuda.cuGetErrorName(error)
        return name if err == cuda.CUresult.CUDA_SUCCESS else "<unknown>"
    elif isinstance(error, cudart.cudaError_t):
        return cudart.cudaGetErrorName(error)[1]
    elif isinstance(error, nvrtc.nvrtcResult):
        return nvrtc.nvrtcGetErrorString(error)[1]
    else:
        raise RuntimeError(f'Unknown error type: {error}')


def check_cuda_errors(result):
    """
    CUDA error handler.
    If the CUDA result is success it returns the remaining objects that
    originally returned by the CUDA function call (if any).
    Otherwise and exception is raised.
    :param result: CUDA function result (CUresult)
    :return: The CUDA function results in case of success
    """
    if result[0].value:
        raise RuntimeError(
            f'CUDA error code = {result[0].value} ({_cuda_get_error_enum(result[0])})')
    if len(result) == 1:
        return None
    elif len(result) == 2:
        return result[1]
    else:
        return result[1:]


# The following functions should not be used directly, instead they should
# replace/extend unittest.TestCase's derived methods in CUDA tests.

@requires_cuda
def setUp(obj):
    super(obj.__class__, obj).setUp()
    obj.iters = 10
    obj.traffic_args = None
    obj.cuda_ctx = None
    obj.init_cuda()


def tearDown(obj):
    if obj.server and obj.server.cuda_addr:
        check_cuda_errors(cuda.cuMemFree(obj.server.cuda_addr))
    if obj.client and obj.client.cuda_addr:
        check_cuda_errors(cuda.cuMemFree(obj.client.cuda_addr))
    if obj.cuda_ctx:
        check_cuda_errors(cuda.cuCtxDestroy(obj.cuda_ctx))
    super(obj.__class__, obj).tearDown()


def init_cuda(obj):
    cuda_dev_id = obj.config['gpu']
    if cuda_dev_id is None:
        raise unittest.SkipTest('GPU device ID must be passed')
    check_cuda_errors(cuda.cuInit(0))
    cuda_device = check_cuda_errors(cuda.cuDeviceGet(cuda_dev_id))
    obj.cuda_ctx = check_cuda_errors(
        cuda.cuCtxCreate(cuda.CUctx_flags.CU_CTX_MAP_HOST, cuda_device))
    check_cuda_errors(cuda.cuCtxSetCurrent(obj.cuda_ctx))


def set_init_cuda_methods(cls):
    """
    Replaces the setUp and tearDown methods of any unittest.TestCase derived
    class. Can be useful as a decorator for CUDA related tests.
    :param cls: Test class of unittest.TestCase
    """
    cls.setUp = setUp
    cls.tearDown = tearDown
    cls.init_cuda = init_cuda
    cls.mem_write = mem_write
    cls.mem_read = mem_read
    return cls


# The following functions should be used by CUDA resources objects

def mem_write(obj, data, size, offset=0):
    cuda_addr = cuda.CUdeviceptr(init_value=int(obj.cuda_addr) + offset)
    check_cuda_errors(cuda.cuMemcpyHtoD(cuda_addr, data.encode(), size))


def mem_read(obj, size=None, offset=0):
    size_ = obj.msg_size if size is None else size
    data_read = bytearray(size_)
    cuda_addr = cuda.CUdeviceptr(init_value=int(obj.cuda_addr) + offset)
    check_cuda_errors(cuda.cuMemcpyDtoH(data_read, cuda_addr, size_))
    return data_read


def set_mem_io_cuda_methods(cls):
    """
    Replaces the mem_write/mem_read methods of any class derived from
    BaseResources.
    :param cls: Test class of BaseResources
    """
    cls.mem_write = mem_write
    cls.mem_read = mem_read
    return cls
