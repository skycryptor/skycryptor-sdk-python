#
import cryptomagic

#
from crypto_magic import CryptoMagic

#
class PublicKey(CryptoMagic):
    def to_bytes(self):
        return cryptomagic.cryptomagic_public_key_to_bytes(self.get_pointer())

    def from_bytes(self, data):
        return cryptomagic.cryptomagic_public_key_from_bytes(self.get_pointer(), data)

    def encapsulate(self):
        cm = CryptoMagic()
        cm.set_pointer(self.get_pointer())
        return cryptomagic.cryptomagic_encapsulate(cm.get_pointer(),self.get_pointer())

    def free(self):
        cryptomagic.cryptomagic_public_key_free(self.get_pointer())
