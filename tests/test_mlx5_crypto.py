import unittest
import struct
import errno
import json
import os

from pyverbs.providers.mlx5.mlx5dv_mkey import Mlx5Mkey, Mlx5MrInterleaved, \
    Mlx5MkeyConfAttr, Mlx5SigCrc, Mlx5SigBlockDomain, Mlx5SigBlockAttr
from pyverbs.providers.mlx5.mlx5dv_crypto import Mlx5CryptoLoginAttr, Mlx5DEK, \
    Mlx5DEKInitAttr, Mlx5CryptoAttr, Mlx5CryptoLogin, Mlx5CryptoExtLoginAttr
from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, \
    Mlx5DVQPInitAttr, Mlx5QP
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError
from tests.mlx5_base import Mlx5RDMATestCase, Mlx5PyverbsAPITestCase
import pyverbs.providers.mlx5.mlx5_enums as dve
from pyverbs.wr import SGE, SendWR, RecvWR
from pyverbs.qp import QPInitAttrEx, QPCap
from tests.base import RCResources
from pyverbs.pd import PD
import pyverbs.enums as e
import tests.utils as u

DEK_OPAQUE = b'dek'

"""
Crytpo operation requires specific input from the user, e.g. the wrapped credential that the
device is configured with. The input should be provided in JSON format in a file in this path:
"/tmp/mlx5_crypto_test.txt".
User can also set this environment variable with his file path: MLX5_CRYPTO_TEST_INFO

This doc describes the input option with examples to the format:
Mandatory:
Wrapped credential: The credential that was configured in the device wrapped.
Wrapped key: Wrapped key for the DEK creation. The key should be encrypted using the KEK
             (Key Encrypted Key).
Optional:
Wrapped 256 bits key: Wrapped key for the DEK creation when the key size of 256 bits is required.
                      If not provided, that test will only use the key in size of 128 bits.
Encrypted data for 512 of 'c': If a user wants to have data validation, he needs to provide
                               expected encrypted data for a plain text of 512 bytes of the
                               character 'c'. If not provided, data validation will be skipped.

Example of content of such file:
[{"credential": [8704278040424473809, 4403447855848063568, 13892768337045135232,
5942481448427925932, 171338997253969038, 5703425261028721211],
"wrapped_key": [contains 5 integers of 64bits each],
"plaintext_key": [contains 8 integers of 32bits each],
"plaintext_256_bits_key": [contains 16 integers of 32bits each],
"encrypted_data_for_512_c": [contains 64 integers of 64bits each],
"wrapped_256_bits_key": [contains 9 integers of 64bits each]}]
"""


def check_crypto_caps(dev_name, is_wrapped_dek_mode, multi_block_support=False):
    """
    Check that this device support crypto actions.
    :param dev_name: The device name.
    :param is_wrapped_dek_mode: True when wrapped_dek and False when plaintext.
    :param multi_block_support: If True, check for multi-block support.
    """
    mlx5dv_attr = Mlx5DVContextAttr()
    ctx = Mlx5Context(mlx5dv_attr, name=dev_name)
    crypto_caps = ctx.query_mlx5_device().crypto_caps
    failed_selftests = crypto_caps['failed_selftests']
    if failed_selftests:
        raise unittest.SkipTest(f'The device crypto selftest failed ({failed_selftests})')
    single_block_cap = dve.MLX5DV_CRYPTO_ENGINES_CAP_AES_XTS_SINGLE_BLOCK \
                       & crypto_caps['crypto_engines']
    multi_block_cap = dve.MLX5DV_CRYPTO_ENGINES_CAP_AES_XTS_MULTI_BLOCK \
                      & crypto_caps['crypto_engines']
    if not single_block_cap and not multi_block_cap:
        raise unittest.SkipTest('The device crypto engines does not support AES')
    elif multi_block_support and not multi_block_cap:
        raise unittest.SkipTest('The device crypto engines does not support multi blocks')
    elif multi_block_cap:
        assert single_block_cap, \
              'The device crypto engines do not support single block but support multi blocks'
    dev_wrapped_import_method = crypto_caps['wrapped_import_method']
    if is_wrapped_dek_mode:
        if not dve.MLX5DV_CRYPTO_WRAPPED_IMPORT_METHOD_CAP_AES_XTS & dev_wrapped_import_method or \
                not dve.MLX5DV_CRYPTO_CAPS_WRAPPED_CRYPTO_OPERATIONAL & crypto_caps['flags']:
            raise unittest.SkipTest('The device does not support wrapped DEK')
    elif dve.MLX5DV_CRYPTO_WRAPPED_IMPORT_METHOD_CAP_AES_XTS & dev_wrapped_import_method and \
                dve.MLX5DV_CRYPTO_CAPS_WRAPPED_CRYPTO_OPERATIONAL & crypto_caps['flags']:
        raise unittest.SkipTest('The device does not support plaintext DEK')


def require_crypto_login_details(instance):
    """
    Parse the crypto login session details from this file:
        '/tmp/mlx5_crypto_test.txt'
    If the file doesn't exists or the content is not in Json format, skip the test.
    :param instance: The test instance.
    """
    crypto_file = '/tmp/mlx5_crypto_test.txt'
    if 'MLX5_CRYPTO_TEST_INFO' in os.environ:
        crypto_file = os.environ['MLX5_CRYPTO_TEST_INFO']
    try:
        with open(crypto_file, 'r') as f:
            test_details = f.read()
            setattr(instance, 'crypto_details', test_details)
            json.loads(test_details)
            instance.crypto_details = json.loads(test_details)[0]
    except json.JSONDecodeError:
        raise unittest.SkipTest(f'The crypto data in {crypto_file} must be in Json format')
    except FileNotFoundError:
        raise unittest.SkipTest(f'Crypto login details must be supplied in {crypto_file}')


def requires_crypto_support(is_wrapped_dek_mode, multi_block_support=False):
    """
    :param is_wrapped_dek_mode: True when wapped_dek and False when plaintext.
    :param multi_block_support: If True, check for multi-block support.
    """
    def outer(func):
        def inner(instance):
            require_crypto_login_details(instance)
            check_crypto_caps(instance.dev_name, is_wrapped_dek_mode, multi_block_support)
            return func(instance)
        return inner
    return outer


class Mlx5CryptoResources(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, dv_send_ops_flags=0,
                 mkey_create_flags=dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT,
                 msg_size=1024):
        self.dv_send_ops_flags = dv_send_ops_flags
        self.mkey_create_flags = mkey_create_flags
        self.max_inline_data = 512
        self.send_ops_flags = e.IBV_QP_EX_WITH_SEND
        super().__init__(dev_name, ib_port, gid_index, msg_size=msg_size)
        self.create_mkeys()

    def create_mkeys(self):
        try:
            self.wire_enc_mkey = Mlx5Mkey(self.pd, self.mkey_create_flags, max_entries=1)
            self.mem_enc_mkey = Mlx5Mkey(self.pd, self.mkey_create_flags, max_entries=1)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create Mkey is not supported')
            raise ex

    def create_qp_cap(self):
        return QPCap(max_send_wr=self.num_msgs, max_recv_wr=self.num_msgs,
                     max_inline_data=self.max_inline_data)

    def create_qp_init_attr(self):
        comp_mask = e.IBV_QP_INIT_ATTR_PD | e.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
        return QPInitAttrEx(cap=self.create_qp_cap(), pd=self.pd, scq=self.cq,
                            rcq=self.cq, qp_type=e.IBV_QPT_RC,
                            send_ops_flags=self.send_ops_flags,
                            comp_mask=comp_mask)

    def create_qps(self):
        try:
            qp_init_attr = self.create_qp_init_attr()
            comp_mask = dve.MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS
            attr = Mlx5DVQPInitAttr(comp_mask=comp_mask,
                                    send_ops_flags=self.dv_send_ops_flags)
            qp = Mlx5QP(self.ctx, qp_init_attr, attr)
            self.qps.append(qp)
            self.qps_num.append(qp.qp_num)
            self.psns.append(0)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create Mlx5DV QP is not supported')
            raise ex


class Mlx5CryptoAPITest(Mlx5PyverbsAPITestCase):
    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self.crypto_details = None

    def verify_create_dek_out_of_login_session(self):
        """
        Verify that create DEK out of crypto login session is not permited.
        """
        with self.assertRaises(PyverbsRDMAError) as ex:
            Mlx5DEK(self.ctx, self.dek_init_attr)
        self.assertEqual(ex.exception.error_code, errno.EINVAL)

    def verify_login_state(self, expected_state):
        """
        Query the session login state and verify that it's as expected.
        """
        state = Mlx5Context.query_login_state(self.ctx)
        self.assertEqual(state, expected_state)

    def verify_login_twice(self):
        """
        Verify that when there is already a login session alive the second login
        fails.
        """
        with self.assertRaises(PyverbsRDMAError) as ex:
            Mlx5Context.crypto_login(self.ctx, self.login_attr)
        self.assertEqual(ex.exception.error_code, errno.EEXIST)

    def verify_dek_opaque(self):
        """
        Query the DEK and verify that its opaque is as expected.
        """
        dek_attr = self.dek.query()
        self.assertEqual(dek_attr.opaque, DEK_OPAQUE)

    @requires_crypto_support(is_wrapped_dek_mode=True)
    def test_mlx5_dek_management(self):
        """
        Test crypto login and DEK management APIs.
        The test checks also that invalid actions are not permited, e.g, create
        DEK not in login session on wrapped DEK mode.
        """
        try:
            self.pd = PD(self.ctx)
            cred_bytes = struct.pack('!6Q', *self.crypto_details['credential'])
            key = struct.pack('!5Q', *self.crypto_details['wrapped_key'])
            self.dek_init_attr = \
                Mlx5DEKInitAttr(self.pd, key=key,
                                key_size=dve.MLX5DV_CRYPTO_KEY_SIZE_128,
                                key_purpose=dve.MLX5DV_CRYPTO_KEY_PURPOSE_AES_XTS,
                                opaque=DEK_OPAQUE)
            self.verify_create_dek_out_of_login_session()
            self.verify_login_state(dve.MLX5DV_CRYPTO_LOGIN_STATE_NO_LOGIN)

            # Login to crypto session
            self.login_attr = Mlx5CryptoLoginAttr(cred_bytes)
            Mlx5Context.crypto_login(self.ctx, self.login_attr)
            self.verify_login_state(dve.MLX5DV_CRYPTO_LOGIN_STATE_VALID)
            self.verify_login_twice()
            self.dek = Mlx5DEK(self.ctx, self.dek_init_attr)
            self.verify_dek_opaque()
            self.dek.close()

            # Logout from crypto session
            Mlx5Context.crypto_logout(self.ctx)
            self.verify_login_state(dve.MLX5DV_CRYPTO_LOGIN_STATE_NO_LOGIN)
        except PyverbsRDMAError as ex:
            print(ex)
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create crypto elements is not supported')
            raise ex


class Mlx5CryptoTrafficTest(Mlx5RDMATestCase):
    """
    Test the mlx5 cryto APIs.
    """
    def setUp(self):
        super().setUp()
        self.iters = 10
        self.crypto_details = None
        self.validate_data = False
        self.is_multi_block = False
        self.msg_size = 1024
        self.key_size = dve.MLX5DV_CRYPTO_KEY_SIZE_128

    def create_client_dek(self):
        """
        Create DEK using the client resources.
        """
        cred_bytes = struct.pack('!6Q', *self.crypto_details['credential'])
        log_attr = Mlx5CryptoLoginAttr(cred_bytes)
        Mlx5Context.crypto_login(self.client.ctx, log_attr)
        self._create_wrapped_dek()

    def create_client_wrapped_dek_login_obj(self):
        """
        Create CryptoExtLoginAttr and crypto login object
        """
        cred_bytes = struct.pack('!6Q', *self.crypto_details['credential'])
        log_attr = Mlx5CryptoExtLoginAttr(cred_bytes, 48)
        crypto_login_obj = Mlx5CryptoLogin(self.client.ctx, log_attr)
        comp_mask=dve.MLX5DV_DEK_INIT_ATTR_CRYPTO_LOGIN
        self._create_wrapped_dek(comp_mask, crypto_login_obj)

    def _create_wrapped_dek(self, comp_mask=0, crypto_login_obj=None):
        """
        Create wrapped DEK using the client resources.
        """
        key = struct.pack('!5Q', *self.crypto_details['wrapped_key'])
        if self.key_size == dve.MLX5DV_CRYPTO_KEY_SIZE_256:
            key = struct.pack('!9Q', *self.crypto_details['wrapped_256_bits_key'])

        if comp_mask == dve.MLX5DV_DEK_INIT_ATTR_CRYPTO_LOGIN:
            self.dek_attr = Mlx5DEKInitAttr(self.client.pd, key=key,
                                            key_size=self.key_size,
                                            key_purpose=dve.MLX5DV_CRYPTO_KEY_PURPOSE_AES_XTS,
                                            comp_mask=comp_mask, crypto_login=crypto_login_obj)
        else:
            self.dek_attr = Mlx5DEKInitAttr(self.client.pd, key=key,
                                            key_size=self.key_size,
                                            key_purpose=dve.MLX5DV_CRYPTO_KEY_PURPOSE_AES_XTS)

        self.dek = Mlx5DEK(self.client.ctx, self.dek_attr)

    def create_client_plaintext_dek(self):
        """
        Create DEK using the client resources.
        """
        key = struct.pack('8I',*self.crypto_details['plaintext_key'])
        if self.key_size == dve.MLX5DV_CRYPTO_KEY_SIZE_256:
            key = struct.pack('16I', *self.crypto_details['plaintext_256_bits_key'])
        self.dek_attr = Mlx5DEKInitAttr(self.client.pd,key=key,
                                        key_size=self.key_size,
                                        comp_mask=dve.MLX5DV_DEK_INIT_ATTR_CRYPTO_LOGIN,
                                        crypto_login=None)
        self.dek = Mlx5DEK(self.client.ctx, self.dek_attr)

    def reg_client_mkey(self, signature=False):
        """
        Configure an mkey with crypto attributes.
        :param signature: True if signature configuration requested.
        """
        num_of_configuration = 4 if signature else 3
        for mkey in [self.client.wire_enc_mkey, self.client.mem_enc_mkey]:
            self.client.qp.wr_start()
            self.client.qp.wr_flags = e.IBV_SEND_SIGNALED | e.IBV_SEND_INLINE
            offset = 0 if mkey == self.client.wire_enc_mkey else self.client.msg_size/2
            sge = SGE(self.client.mr.buf + offset, self.client.msg_size/2, self.client.mr.lkey)
            self.client.qp.wr_mkey_configure(mkey, num_of_configuration, Mlx5MkeyConfAttr())
            self.client.qp.wr_set_mkey_access_flags(e.IBV_ACCESS_LOCAL_WRITE)
            self.client.qp.wr_set_mkey_layout_list([sge])
            if signature:
                self.configure_mkey_signature()
            initial_tweak = struct.pack('!2Q', int(0), int(0))
            encrypt_on_tx = mkey == self.client.wire_enc_mkey
            sign_crypto_order = dve.MLX5DV_SIGNATURE_CRYPTO_ORDER_SIGNATURE_BEFORE_CRYPTO_ON_TX
            crypto_attr = Mlx5CryptoAttr(crypto_standard=dve.MLX5DV_CRYPTO_STANDARD_AES_XTS,
                                         encrypt_on_tx=encrypt_on_tx,
                                         signature_crypto_order=sign_crypto_order,
                                         data_unit_size=dve.MLX5DV_BLOCK_SIZE_512,
                                         dek=self.dek, initial_tweak=initial_tweak)
            self.client.qp.wr_set_mkey_crypto(crypto_attr)
            self.client.qp.wr_complete()
            u.poll_cq(self.client.cq)

    def configure_mkey_signature(self):
        """
        Configure an mkey with signature attributes.
        """
        sig_crc = Mlx5SigCrc(crc_type=dve.MLX5DV_SIG_CRC_TYPE_CRC32, seed=0xFFFFFFFF)
        sig_block_domain = Mlx5SigBlockDomain(sig_type=dve.MLX5DV_SIG_TYPE_CRC, crc=sig_crc,
                                              block_size=dve.MLX5DV_BLOCK_SIZE_512)
        sig_attr = Mlx5SigBlockAttr(wire=sig_block_domain,
                                    check_mask=dve.MLX5DV_SIG_MASK_CRC32)
        self.client.qp.wr_set_mkey_sig_block(sig_attr)

    def get_send_wr(self, player, wire_encryption):
        mkey = player.wire_enc_mkey if wire_encryption else player.mem_enc_mkey
        sge = SGE(0, player.msg_size/2, mkey.lkey)
        return SendWR(opcode=e.IBV_WR_SEND, num_sge=1, sg=[sge])

    def get_recv_wr(self, player, wire_encryption):
        offset = 0 if wire_encryption else player.msg_size/2
        sge = SGE(player.mr.buf + offset, player.msg_size/2, player.mr.lkey)
        return RecvWR(sg=[sge], num_sge=1)

    def prepare_validate_data(self):
        data_size = int(self.msg_size / 2)
        self.client.mr.write('c' * data_size, data_size)
        if self.is_multi_block:
            encrypted_data = struct.pack('!128Q', *self.crypto_details['encrypted_data_for_1024_c'])
        else:
            encrypted_data = struct.pack('!64Q', *self.crypto_details['encrypted_data_for_512_c'])
        self.client.mr.write(encrypted_data, data_size, offset=data_size)

    def validate_crypto_data(self):
        """
        Validate the server MR data. Verify that the encryption/decryption works well.
        """
        data_size= int(self.msg_size / 2)
        send_msg = self.client.mr.read(self.msg_size, 0)
        recv_msg = self.server.mr.read(self.msg_size, 0)
        self.assertEqual(send_msg[0:data_size], recv_msg[data_size:self.msg_size])
        self.assertEqual(send_msg[data_size:self.msg_size], recv_msg[0:data_size])

    def init_data_validation(self):
        if 'encrypted_data_for_512_c' in self.crypto_details and not self.is_multi_block:
            self.validate_data = True
        elif 'encrypted_data_for_1024_c' in self.crypto_details and self.is_multi_block:
            self.validate_data = True

    def traffic(self):
        """
        Perform RC traffic using the configured mkeys.
        """
        if self.validate_data:
            self.prepare_validate_data()
        for _ in range(self.iters):
            self.server.qp.post_recv(self.get_recv_wr(self.server, wire_encryption=True))
            self.server.qp.post_recv(self.get_recv_wr(self.server, wire_encryption=False))
            self.client.qp.post_send(self.get_send_wr(self.client, wire_encryption=True))
            self.client.qp.post_send(self.get_send_wr(self.client, wire_encryption=False))
            u.poll_cq(self.client.cq, count=2)
            u.poll_cq(self.server.cq, count=2)
            if self.validate_data:
                self.validate_crypto_data()

    def run_crypto_dek_test(self, create_dek_func):
        """
        Creates player and DEK, using the give function, for different test
        cases, and runs traffic.
        :param create_dek_func: Function that creates a DEK.
        """
        self.init_data_validation()
        mkey_flags = dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_CRYPTO | \
            dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT
        self.create_players(Mlx5CryptoResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
                            mkey_create_flags=mkey_flags, msg_size=self.msg_size)
        create_dek_func()
        self.reg_client_mkey()
        self.traffic()

    @requires_crypto_support(is_wrapped_dek_mode=True)
    def test_mlx5_crypto_mkey_old_api(self):
        """
        Create Mkeys, register a memory layout using the mkeys, configure
        crypto attributes on it and then run traffic.
        """
        self.run_crypto_dek_test(self.create_client_dek)

    @requires_crypto_support(is_wrapped_dek_mode=True)
    def test_mlx5_crypto_wrapped_dek(self):
        """
        Create Mkeys, register a memory layout using the mkeys,
        configure crypto attributes on it using login object API and then run
        traffic.
        Use wrapped DEK with new API.
        """
        self.run_crypto_dek_test(self.create_client_wrapped_dek_login_obj)

    @requires_crypto_support(is_wrapped_dek_mode=False)
    def test_mlx5_crypto_plaintext_dek(self):
        """
        Create Mkeys, register a memory layout using the mkeys,
        configure crypto attributes on it using login object API and then run
        traffic.
        Use plaintext DEK.
        """
        self.run_crypto_dek_test(self.create_client_plaintext_dek)

    @requires_crypto_support(is_wrapped_dek_mode=True)
    def test_mlx5_crypto_signature_mkey(self):
        """
        Create Mkeys, register a memory layout using this mkey, configure
        crypto and signature attributes on it and then perform traffic using
        this mkey.
        """
        if 'wrapped_256_bits_key' in self.crypto_details:
            self.key_size = dve.MLX5DV_CRYPTO_KEY_SIZE_256
        mkey_flags = dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_CRYPTO | \
                     dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT | \
                     dve.MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE
        self.create_players(Mlx5CryptoResources,
                            dv_send_ops_flags=dve.MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
                            mkey_create_flags=mkey_flags)
        self.create_client_dek()
        self.reg_client_mkey(signature=True)
        self.traffic()

    @requires_crypto_support(is_wrapped_dek_mode=False, multi_block_support=True)
    def test_mlx5_plaintext_dek_multi_block(self):
        self.is_multi_block = True
        self.msg_size = 2048
        self.run_crypto_dek_test(self.create_client_plaintext_dek)

    @requires_crypto_support(is_wrapped_dek_mode=True, multi_block_support=True)
    def test_mlx5_wrapped_dek_multi_block(self):
        self.is_multi_block = True
        self.msg_size = 2048
        self.run_crypto_dek_test(self.create_client_wrapped_dek_login_obj)
