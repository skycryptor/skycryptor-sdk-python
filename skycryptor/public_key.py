#
import binascii
import cryptomagic

#
from crypto_magic import CryptoMagic
from capsule import Capsule

#
class PublicKey(CryptoMagic):
    def __init__(self, cm):
        self.cm = cm
        super().__init__()

    def to_bytes(self):
        return binascii.hexlify(cryptomagic.cryptomagic_public_key_to_bytes(self.get_pointer()))

    def from_bytes(self, data):
        self.set_pointer(cryptomagic.cryptomagic_public_key_from_bytes(self.get_pointer(), binascii.unhexlify(data)))

    def encapsulate(self):
        capsule = Capsule()
        capsule_pointer, symmetric_key = cryptomagic.cryptomagic_encapsulate(self.cm.get_pointer(),self.get_pointer())
        capsule.set_pointer(capsule_pointer) 
        return capsule, symmetric_key

    def free(self):
        cryptomagic.cryptomagic_public_key_free(self.get_pointer())
