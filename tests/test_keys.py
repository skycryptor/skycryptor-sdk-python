#
import sys
sys.path.insert(0,'/home/gegham/Desktop/skycryptor-sdk-python')

#
import skycryptor
import binascii

#
from cryptomagic_test import TestCryptoMagic

from skycryptor.skycryptor import SkyCryptor 
from skycryptor.private_key import PrivateKey
from skycryptor.public_key import PublicKey 
#
class KeyFromToBytes(TestCryptoMagic):
    #
    def setUp(self):
        super(KeyFromToBytes, self).setUp()

    #
    def test_public_key_from_to_bytes(self):
        sc = SkyCryptor()
        sk = sc.generate()  
 
        pk_1 = sk.get_public_key()

        pk_data_1 = pk_1.to_bytes()
        pk_2 = sc.public_key_from_bytes(pk_data_1)

        pk_data_2 = pk_2.to_bytes()

        self.assertEqual(pk_data_1, pk_data_2)


    def test_private_key_from_to_bytes(self):
        sc = SkyCryptor()
        sk_1 = sc.generate()  
        
        sk_data_1 = sk_1.to_bytes()
        sk_2 = sc.private_key_from_bytes(sk_data_1)
      
        sk_data_2 = sk_2.to_bytes()
        self.assertEqual(sk_data_1, sk_data_2) 
