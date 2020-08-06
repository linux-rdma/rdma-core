# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2018, Mellanox Technologies. All rights reserved.
import os


class PyverbsError(Exception):
    """
    Base exception class for Pyverbs. Inherited by PyverbsRDMAError (for errors
    returned by rdma-core) and PyverbsUserError (for user-related errors
    found by Pyverbs,  e.g. non-existing device name).
    """
    def __init__(self, msg, error_code = -1):
        """
        Initializes a PyverbsError instance
        :param msg: The exception's message
        :param error_code: errno value
        """
        if error_code != -1:
            msg = '{msg}. Errno: {err}, {err_str}'.\
                format(msg=msg, err=error_code, err_str=os.strerror(error_code))
        super(PyverbsError, self).__init__(msg)

class PyverbsRDMAError(PyverbsError):
    """
    This exception is raised when an rdma-core function returns an error.
    """
    def __init__(self, msg, error_code = -1):
        super(PyverbsRDMAError, self).__init__(msg, error_code)
        self._error_code = error_code

    @property
    def error_code(self):
        return self._error_code


class PyverbsUserError(PyverbsError):
    """
    This exception is raised when Pyverbs encounters an error resulting from
    user's action or input.
    """
    def __init__(self, msg):
        """
        Initializes a PyverbsUserError instance
        :param msg: The exception's message
        """
        super(PyverbsUserError, self).__init__(msg)

