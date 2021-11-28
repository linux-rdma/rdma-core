# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2021 Nvidia, Inc. All rights reserved. See COPYING file

from libc.string cimport memcpy

from pyverbs.pyverbs_error import PyverbsRDMAError
cimport pyverbs.providers.mlx5.libmlx5 as dv
from pyverbs.base import PyverbsRDMAErrno
from pyverbs.device cimport Context
from pyverbs.pd cimport PD


cdef class Mlx5CryptoLoginAttr(PyverbsObject):
    def __init__(self, credential, credential_id=0, import_kek_id=0):
        """
        Initializes a Mlx5CryptoLoginAttr object representing
        mlx5dv_crypto_login_attr C struct.
        :param credential: The credential to login with. Must be provided
                           wrapped by the AES key wrap algorithm using the
                           import KEK indicated by *import_kek_id*.
        :param credential_id: The index of credential that stored on the device.
        :param import_kek_id: The index of import_kek that stored on the device.
        """
        cdef char *credential_c = credential
        self.mlx5dv_crypto_login_attr.credential_id = credential_id
        self.mlx5dv_crypto_login_attr.import_kek_id = import_kek_id
        memcpy(self.mlx5dv_crypto_login_attr.credential, credential_c, 48)

    @property
    def credential_id(self):
        return self.mlx5dv_crypto_login_attr.credential_id

    @property
    def import_kek_id(self):
        return self.mlx5dv_crypto_login_attr.import_kek_id

    @property
    def credential(self):
        return self.mlx5dv_crypto_login_attr.credential

    @property
    def comp_mask(self):
        return self.mlx5dv_crypto_login_attr.comp_mask

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return 'Mlx5CryptoLoginAttr:\n' +\
               print_format.format('Credential id', self.credential_id) +\
               print_format.format('Import KEK id', self.import_kek_id) +\
               print_format.format('Credential', self.credential) +\
               print_format.format('Comp mask', self.comp_mask)


cdef class Mlx5DEKInitAttr(PyverbsObject):
    def __init__(self, PD pd, key_size, has_keytag=False, key_purpose=0, opaque=bytes(),
                 key=bytes(), comp_mask=0):
        """
        Initializes a Mlx5DEKInitAttr object representing mlx5dv_dek_init_attr
        C struct.
        :param pd: The protection domain to be associated with the DEK.
        :param credential_id: The size of the key,
                              can be MLX5DV_CRYPTO_KEY_SIZE_128/256
        :param has_keytag: Whether the DEK has a keytag or not. If set, the key
                           should include a 8 Bytes keytag.
        :param key_purpose: The crypto purpose of the key.
        :param opaque: Plaintext metadata to describe the key.
        :param key: The key itself, wrapped by the crypto login session's
                    import KEK.
        :param comp_mask: Reserved for future extension.
        """
        cdef char *opaque_c = opaque
        cdef char *key_c = key
        self.pd = pd
        self.mlx5dv_dek_init_attr.pd = pd.pd
        self.mlx5dv_dek_init_attr.key_size = key_size
        self.mlx5dv_dek_init_attr.has_keytag = has_keytag
        self.mlx5dv_dek_init_attr.key_purpose = key_purpose
        memcpy(self.mlx5dv_dek_init_attr.opaque, opaque_c, 8)
        memcpy(self.mlx5dv_dek_init_attr.key, key_c, 128)
        self.mlx5dv_dek_init_attr.comp_mask = comp_mask

    @property
    def key_size(self):
        return self.mlx5dv_dek_init_attr.key_size

    @property
    def has_keytag(self):
        return self.mlx5dv_dek_init_attr.has_keytag

    @property
    def key_purpose(self):
        return self.mlx5dv_dek_init_attr.key_purpose

    @property
    def opaque(self):
        return self.mlx5dv_dek_init_attr.opaque.decode()

    @property
    def key(self):
        return self.mlx5dv_dek_init_attr.key.hex()

    @property
    def comp_mask(self):
        return self.mlx5dv_dek_init_attr.comp_mask

    def __str__(self):
        print_format = '{:20}: {:<20}\n'
        return 'Mlx5DEKInitAttr:\n' +\
            print_format.format('key_size', self.key_size) +\
            print_format.format('Has keytag', self.has_keytag) +\
            print_format.format('Key purpose', self.key_purpose) +\
            print_format.format('Opaque', self.opaque) +\
            print_format.format('Key (in hex format)', self.key) +\
            print_format.format('Comp mask', self.comp_mask)


cdef class Mlx5DEKAttr(PyverbsObject):
    """
    Initializes a Mlx5DEKAttr object representing mlx5dv_dek_attr
    C struct.
    """
    @property
    def state(self):
        return self.mlx5dv_dek_attr.state

    @property
    def opaque(self):
        return self.mlx5dv_dek_attr.opaque

    @property
    def comp_mask(self):
        return self.mlx5dv_dek_attr.comp_mask


cdef class Mlx5CryptoAttr(PyverbsObject):
    def __init__(self, crypto_standard=0, encrypt_on_tx=False, signature_crypto_order=0,
                 data_unit_size=0, initial_tweak=bytes(), Mlx5DEK dek=None,
                 keytag=bytes(), comp_mask=0):
        """
        Initializes a Mlx5CryptoAttr object representing mlx5dv_crypto_attr
        C struct.
        :param crypto_standard: The encryption standard that should be used.
        :param encrypt_on_tx: If set, memory data will be encrypted during TX
                              and wire data will be decrypted during RX.
        :param signature_crypto_order: Controls the order between crypto and
                                       signature operations. Relevant only if
                                       signature is configured.
        :param data_unit_size: The tweak is	incremented after each
                               *data_unit_size* during the encryption.
        :param initial_tweak: A value to be used during encryption of each data
                              unit. This value is incremented by the device for
                              every data unit in the message
        :param dek: The DEK to be used for the crypto operations.
        :param keytag: A tag that verifies that the correct DEK is being used.
        :param comp_mask: Reserved for future extension.
        """
        cdef char *initial_tweak_c = initial_tweak
        cdef char *keytag_c = keytag
        self.mlx5dv_crypto_attr.crypto_standard = crypto_standard
        self.mlx5dv_crypto_attr.encrypt_on_tx = encrypt_on_tx
        self.mlx5dv_crypto_attr.signature_crypto_order = signature_crypto_order
        self.mlx5dv_crypto_attr.data_unit_size = data_unit_size
        memcpy(self.mlx5dv_crypto_attr.initial_tweak, initial_tweak_c, 16)
        self.mlx5dv_crypto_attr.dek = dek.mlx5dv_dek
        memcpy(self.mlx5dv_crypto_attr.keytag, keytag_c, 8)
        self.mlx5dv_crypto_attr.comp_mask = comp_mask

    @property
    def crypto_standard(self):
        return self.mlx5dv_crypto_attr.crypto_standard

    @property
    def encrypt_on_tx(self):
        return self.mlx5dv_crypto_attr.encrypt_on_tx

    @property
    def signature_crypto_order(self):
        return self.mlx5dv_crypto_attr.signature_crypto_order

    @property
    def data_unit_size(self):
        return self.mlx5dv_crypto_attr.data_unit_size

    @property
    def initial_tweak(self):
        return self.mlx5dv_crypto_attr.initial_tweak.hex()

    @property
    def keytag(self):
        print('@keytag')
        return self.mlx5dv_crypto_attr.keytag.hex()

    @property
    def comp_mask(self):
        return self.mlx5dv_crypto_attr.comp_mask

    def __str__(self):
        print_format = '{:30}: {:<20}\n'
        return 'Mlx5CryptoAttr:\n' +\
            print_format.format('Crypto standard', self.crypto_standard) +\
            print_format.format('Encrypt on TX', self.encrypt_on_tx) +\
            print_format.format('Signature crypto order', self.signature_crypto_order) +\
            print_format.format('Data unit size', self.data_unit_size) +\
            print_format.format('Initial tweak (in hex format)', self.initial_tweak) +\
            print_format.format('keytag (in hex format)', self.keytag) +\
            print_format.format('Comp mask', self.comp_mask)


cdef class Mlx5DEK(PyverbsCM):
    def __init__(self, Context ctx, Mlx5DEKInitAttr dek_init_attr):
        """
        Create a Mlx5DEK object.
        :param context: Context to create the schedule resources on.
        :param dek_init_attr: Mlx5DEKInitAttr, containing the DEK attributes.
        """
        self.mlx5dv_dek = dv.mlx5dv_dek_create(ctx.context,
                                               &dek_init_attr.mlx5dv_dek_init_attr)
        if self.mlx5dv_dek == NULL:
            raise PyverbsRDMAErrno('Failed to create DEK')
        self.pd = dek_init_attr.pd
        self.pd.deks.add(self)

    def query(self):
        """
        Query the dek state.
        :return: Mlx5DEKAttr which contains the dek state and opaque.
        """
        dek_attr = Mlx5DEKAttr()
        rc = dv.mlx5dv_dek_query(self.mlx5dv_dek, &dek_attr.mlx5dv_dek_attr)
        if rc:
            raise PyverbsRDMAError('Failed to query the dek', rc)
        return dek_attr

    def __dealloc__(self):
        self.close()

    cpdef close(self):
        if self.mlx5dv_dek != NULL:
            rc = dv.mlx5dv_dek_destroy(self.mlx5dv_dek)
            if rc:
                raise PyverbsRDMAError('Failed to destroy a DEK', rc)
            self.mlx5dv_dek = NULL
            self.pd = None
