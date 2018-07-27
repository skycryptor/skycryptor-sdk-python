#
import cryptomagic

#
from crypto_magic import CryptoMagic, Key
from private_key import PrivateKey
from public_key import PublicKey
from capsule import Capsule

#
class SkyCryptor(CryptoMagic):
    def __init__(self):
        pass

    def generate(self):
        sk = PrivateKey()
        sk.generate()
        return sk

    def private_key_from_bytes(self, data):
        sk = PrivateKey()
        sk.set_pointer = self.get_pointer()
        sk.from_bytes(data)
        return sk

    def public_key_from_bytes(self):
        pk = PublicKey()
        pk.set_pointer = self.get_pointer()
        pk.from_bytes(data)
        return pk
         
    def capsule_from_bytes(self):
        cs = Capsule()
        cs.set_pointer = self.get_pointer()
        cs.from_bytes(data)
        return cs

    def re_encryption_key_from_bytes(self):
        rk = Capsule()
        rk.set_pointer = self.get_pointer()
        rk.from_bytes(data)
        return rk

    def free(self):
        self.clear() 

