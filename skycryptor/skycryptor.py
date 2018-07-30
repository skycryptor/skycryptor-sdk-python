#
import cryptomagic

#
from crypto_magic import CryptoMagic
from private_key import PrivateKey
from public_key import PublicKey
from capsule import Capsule
from re_key import ReEncryptionKey

#
class SkyCryptor(CryptoMagic):
    def generate(self):
        sk = PrivateKey(CryptoMagic())
        sk.generate()
        return sk

    def private_key_from_bytes(self, data):
        sk = PrivateKey(CryptoMagic())
        sk.set_pointer(self.get_pointer())
        sk.from_bytes(data)
        return sk

    def public_key_from_bytes(self, data):
        pk = PublicKey(CryptoMagic())
        pk.set_pointer(self.get_pointer())
        pk.from_bytes(data)
        return pk
         
    def capsule_from_bytes(self, data):
        cs = Capsule()
        cs.set_pointer(self.get_pointer())
        cs.from_bytes(data)
        return cs

    def re_encryption_key_from_bytes(self, data):
        rk = ReEncryptionKey()
        rk.set_pointer(self.get_pointer())
        rk.from_bytes(data)
        return rk

    def free(self):
        self.clear() 

