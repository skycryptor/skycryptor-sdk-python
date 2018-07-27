#
import cryptomagic

#
from crypto_magic import CryptoMagic

#
class Capsule(CryptoMagic):
    def to_bytes(self):
        return cryptomagic.cryptomagic_capsule_to_bytes(self.get_pointer())

    def from_bytes(self, data):
        return cryptomagic.cryptomagic_capsule_to_bytes(self.get_pointer())

    def free(self):
        cryptomagic.cryptomagic_capsule_free(self.get_pointer())
