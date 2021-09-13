# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

from pyverbs.pyverbs_error import PyverbsUserError, PyverbsRDMAError
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.pd cimport PD


cdef class Mlx5SigCrc(PyverbsObject):
    def __init__(self, crc_type=0, seed=0):
        """
        Initializes a Mlx5SigCrc object representing mlx5dv_sig_crc C struct.
        :param crc_type: The specific CRC type.
        :param seed: A seed for the CRC calculation per block.
        """
        self.mlx5dv_sig_crc.type = crc_type
        self.mlx5dv_sig_crc.seed = seed


cdef class Mlx5SigT10Dif(PyverbsObject):
    def __init__(self, bg_type=0, bg=0, app_tag=0, ref_tag=0, flags=0):
        """
        Initializes a Mlx5SigT10Dif object representing mlx5dv_sig_t10dif
        C struct.
        :param bg_type: The block guard type to be used.
        :param bg: A seed for the block guard calculation per block.
        :param app_tag: An application tag to generate or validate.
        :param ref_tag: A reference tag to generate or validate.
        :param flags: Flags for the T10DIF attributes.
        """
        self.mlx5dv_sig_t10dif.bg_type = bg_type
        self.mlx5dv_sig_t10dif.bg = bg
        self.mlx5dv_sig_t10dif.app_tag = app_tag
        self.mlx5dv_sig_t10dif.ref_tag = ref_tag
        self.mlx5dv_sig_t10dif.flags = flags


cdef class Mlx5SigBlockDomain(PyverbsObject):
    def __init__(self, sig_type=0, Mlx5SigT10Dif dif=None,
                 Mlx5SigCrc crc=None, block_size=0, comp_mask=0):
        """
        Initializes a Mlx5SigBlockDomain object representing
        mlx5dv_sig_block_domain C struct.
        :param sig_type: The signature type for this domain.
        :param dif: Mlx5SigT10Dif object.
        :param crc: Mlx5SigCrc object.
        :param block_size: The block size for this domain.
        :param comp_mask: Compatibility mask.
        """
        self.mlx5dv_sig_block_domain.sig_type = sig_type
        self.mlx5dv_sig_block_domain.block_size = block_size
        self.mlx5dv_sig_block_domain.comp_mask = comp_mask
        if dif:
            self.mlx5dv_sig_block_domain.sig.dif = &dif.mlx5dv_sig_t10dif
        if crc:
            self.mlx5dv_sig_block_domain.sig.crc = &crc.mlx5dv_sig_crc


cdef class Mlx5SigBlockAttr(PyverbsObject):
    def __init__(self, Mlx5SigBlockDomain mem=None, Mlx5SigBlockDomain wire=None,
                 flags=0, check_mask=0, copy_mask=0, comp_mask=0):
        """
        Initializes a Mlx5SigBlockAttr object representing
        mlx5dv_sig_block_attr C struct.
        :param mem: Mlx5SigBlockDomain of the signature configuration for the
                    memory domain or None if the domain does not have a
                    signature.
        :param wire: Mlx5SigBlockDomain of the signature configuration for the
                     wire domain or None if the domain does not have a
                     signature.
        :param flags: Flags for the block signature attributes.
        :param check_mask: Byte of the input signature is checked if
                           corresponding bit in check_mask is set.
        :param copy_mask: Byte of the signature is copied from the source
                          domain to the destination domain if corresponding
                          bit in copy_mask is set.
        :param comp_mask: Compatibility mask.
        """
        self.mlx5dv_sig_block_attr.flags = flags
        self.mlx5dv_sig_block_attr.check_mask = check_mask
        self.mlx5dv_sig_block_attr.copy_mask = copy_mask
        self.mlx5dv_sig_block_attr.comp_mask = comp_mask
        if mem:
            self.mlx5dv_sig_block_attr.mem = &mem.mlx5dv_sig_block_domain
        if wire:
            self.mlx5dv_sig_block_attr.wire = &wire.mlx5dv_sig_block_domain


cdef class Mlx5SigErr(PyverbsObject):
    def __init__(self, actual_value=0, expected_value=0, offset=0):
        """
        Initializes a Mlx5SigBlockAttr object representing
        mlx5dv_sig_block_attr C struct.
        :param actual_value: The actual value that was calculated from the
                             transferred data.
        :param expected_value: The expected value based on what appears in the
                               signature respected field.
        :param offset: The offset within the transfer where the error happened.
        """
        self.mlx5dv_sig_err.actual_value = actual_value
        self.mlx5dv_sig_err.expected_value = expected_value
        self.mlx5dv_sig_err.offset = offset

    @property
    def actual_value(self):
        return self.mlx5dv_sig_err.actual_value

    @property
    def expected_value(self):
        return self.mlx5dv_sig_err.expected_value

    @property
    def offset(self):
        return self.mlx5dv_sig_err.offset


cdef class Mlx5MkeyErr(PyverbsObject):
    def __init__(self, Mlx5SigErr sig_err=Mlx5SigErr(),
                 err_type=dv.MLX5DV_MKEY_NO_ERR):
        """
        Initializes a Mlx5MkeyErr object representing mlx5dv_mkey_err
        C struct.
        :param sig_err: Mlx5SigErr object that handle the sig error.
        :param err_type: Indicate what kind of error happened.
        """
        self.mlx5dv_mkey_err.err_type = err_type
        self.mlx5dv_mkey_err.err.sig = sig_err.mlx5dv_sig_err

    @property
    def err_type(self):
        return self.mlx5dv_mkey_err.err_type

    @property
    def sig_err(self):
        return Mlx5SigErr(self.mlx5dv_mkey_err.err.sig.actual_value,
                          self.mlx5dv_mkey_err.err.sig.expected_value,
                          self.mlx5dv_mkey_err.err.sig.offset)


cdef class Mlx5MkeyConfAttr(PyverbsObject):
    def __init__(self, conf_flags=0, comp_mask=0):
        """
        Initializes a Mlx5MkeyConfAttr object representing mlx5dv_mkey_conf_attr
        C struct.
        :param conf_flags: Mkey configuration flags.
        :param comp_mask: Compatibility mask.
        """
        self.mlx5dv_mkey_conf_attr.conf_flags = conf_flags
        self.mlx5dv_mkey_conf_attr.comp_mask = comp_mask


cdef class Mlx5MrInterleaved(PyverbsObject):
    def __init__(self, addr, bytes_count, bytes_skip, lkey):
        """
        Initializes a Mlx5MrInterleaved object representing mlx5dv_mr_interleaved
        C struct.
        :param addr: The start of address.
        :param bytes_count: Count of bytes from the address that will hold the
                            real data.
        :param bytes_skip: Count of bytes to skip after the bytes_count.
        :param lkey: The lkey of this memory.
        """
        self.mlx5dv_mr_interleaved.addr = addr
        self.mlx5dv_mr_interleaved.bytes_count = bytes_count
        self.mlx5dv_mr_interleaved.bytes_skip = bytes_skip
        self.mlx5dv_mr_interleaved.lkey = lkey


cdef class Mlx5Mkey(PyverbsCM):
    def __init__(self, PD pd not None, create_flags, max_entries):
        """
        Creates an indirect mkey and store the actual mkey max_entries after the
        mkey creation.
        :param pd: PD instance.
        :param create_flags: Mkey creation flags.
        :param max_entries: Requested max number of pointed entries by this
                            indirect mkey.
        """
        cdef dv.mlx5dv_mkey_init_attr mkey_init
        mkey_init.pd = pd.pd
        mkey_init.create_flags = create_flags
        mkey_init.max_entries = max_entries
        self.mlx5dv_mkey = dv.mlx5dv_create_mkey(&mkey_init)
        if self.mlx5dv_mkey == NULL:
            raise PyverbsRDMAErrno('Failed to create mkey')
        self.max_entries = mkey_init.max_entries
        self.pd = pd
        self.pd.mkeys.add(self)

    def mkey_check(self):
        """
        Checks the mkey for errors and provides the result in err_info on success.
        :return: Mlx5MkeyErr object, the result of the Mkey check.
        """
        mkey_err = Mlx5MkeyErr()
        rc = dv.mlx5dv_mkey_check(self.mlx5dv_mkey, &mkey_err.mlx5dv_mkey_err)
        if rc:
            raise PyverbsRDMAError('Failed to check the mkey', rc)
        return mkey_err

    @property
    def lkey(self):
        return self.mlx5dv_mkey.lkey

    @property
    def rkey(self):
        return self.mlx5dv_mkey.rkey

    @property
    def max_entries(self):
        return self.max_entries

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.mlx5dv_mkey != NULL:
            rc = dv.mlx5dv_destroy_mkey(self.mlx5dv_mkey)
            if rc:
                raise PyverbsRDMAError('Failed to destroy a mkey', rc)
            self.mlx5dv_mkey = NULL
            self.pd = None
