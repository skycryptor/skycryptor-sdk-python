import sys
sys.path.insert(0,'/home/gegham/Desktop/skycryptor-sdk-python')

#
import skycryptor

#
from skycryptor import cryptomagic

#
from skycryptor.skycryptor import SkyCryptor
from skycryptor.private_key import PrivateKey
from skycryptor.public_key import PublicKey 
from cryptomagic_test import TestCryptoMagic

#
class Capsule(TestCryptoMagic):
    #
    def setUp(self):
        super(Capsule, self).setUp()

    #
    def test_capsule_from_to_bytes(self):
        sc = SkyCryptor()
        sk = sc.generate()
        pk = sk.get_public_key()
       
        capsule_1, _ = pk.encapsulate()
        cData_1 = capsule_1.to_bytes()
        capsule_2 = sc.capsule_from_bytes(cData_1)
        cData_2 = capsule_2.to_bytes()

        self.assertEqual(cData_1, cData_2)

    def test_encapsulate_decapsulate(self):
        sc = SkyCryptor()
        sk = sc.generate()
        pk = sk.get_public_key()

        capsule_1, sym_key_1 = pk.encapsulate()
        cData_1 = capsule_1.to_bytes()

        capsule_2 = sc.capsule_from_bytes(cData_1)
        cData_2 = capsule_2.to_bytes()

        self.assertEqual(cData_1, cData_2)
 


