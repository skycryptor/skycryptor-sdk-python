#
import binascii
import cryptomagic

#
from .crypto_magic import CryptoMagic

#
class Capsule(CryptoMagic):
    def to_bytes(self):
        return binascii.hexlify(cryptomagic.cryptomagic_capsule_to_bytes(self.get_pointer()))

    def from_bytes(self, data):
        self.set_pointer(cryptomagic.cryptomagic_capsule_from_bytes(self.get_pointer(), binascii.unhexlify(data)))

    def free(self):
        cryptomagic.cryptomagic_capsule_free(self.get_pointer())
