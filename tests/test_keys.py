#
import os

#
from proxylib_test import TestProxyLib

import skycryptor
from skycryptor.skycryptor import SkyCryptor


#
class KeyFromToBytes(TestProxyLib):
    #
    def setUp(self):
        super(KeyFromToBytes, self).setUp()

    #
    def test_public_key_from_to_bytes(self):
        Skycryptor = SkyCryptor()
        sk = Skycryptor.generate()

        pk_1 = Skycryptor.public_key(sk)

        pk_data_1 = pk_1.to_bytes()
        pk_2 = Skycryptor.public_key_from_bytes(pk_data_1)

        pk_data_2 = pk_2.to_bytes()

        self.assertEqual(pk_data_1, pk_data_2)

    def test_private_key_from_to_bytes(self):
        Skycryptor = SkyCryptor()
        sk_1 = Skycryptor.generate()

        sk_data_1 = sk_1.to_bytes()
        sk_2 = Skycryptor.private_key_from_bytes(sk_data_1)

        sk_data_2 = sk_2.to_bytes()
        self.assertEqual(sk_data_1, sk_data_2)
