#
import os

#
from proxylib_test import TestProxyLib

import skycryptor
from skycryptor.skycryptor import SkyCryptor

#
class ReKeyFromToBytes(TestProxyLib):
    #
    def setUp(self):
        super(ReKeyFromToBytes, self).setUp()

    #
    def test_re_key_from_to_bytes(self):
        Skycryptor = SkyCryptor()
        skA = Skycryptor.generate()
        skB = Skycryptor.generate()
        pkB = Skycryptor.public_key(skB)

        rkAB_1 = Skycryptor.generate_re_key(skA, pkB)

        rkAB_1_data = rkAB_1.to_bytes()

        rkAB_2 = Skycryptor.re_encryption_key_from_bytes(rkAB_1_data)

        rkAB_2_data = rkAB_2.to_bytes()

        self.assertEqual(rkAB_1_data, rkAB_2_data)
