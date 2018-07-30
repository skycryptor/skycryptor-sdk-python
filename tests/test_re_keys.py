import sys
sys.path.insert(0,'/home/gegham/Desktop/skycryptor-sdk-python')

#
import skycryptor
import binascii
#
from skycryptor import cryptomagic

#
from skycryptor.skycryptor import SkyCryptor
from skycryptor.private_key import PrivateKey
from skycryptor.public_key import PublicKey 
from cryptomagic_test import TestCryptoMagic

#
class ReKeyFromToBytes(TestCryptoMagic):
    #
    def setUp(self):
        super(ReKeyFromToBytes, self).setUp()

    #
    def test_re_key_from_to_bytes(self):
        sc = SkyCryptor()
        skA = sc.generate()
        skB = sc.generate()
        pkB = skB.get_public_key()
        
        rkAB_1 = skA.generate_re_encryption_key(pkB)
        
        rkAB_1_data = rkAB_1.to_bytes()       
        
        rkAB_2 = sc.re_encryption_key_from_bytes(rkAB_1_data)
        
        rkAB_2_data = rkAB_2.to_bytes()

        self.assertEqual(rkAB_1_data, rkAB_2_data)
