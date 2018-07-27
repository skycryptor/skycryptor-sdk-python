#
import cryptomagic

#
from crypto_magic import CryptoMagic

#
class ReEncryptionKey(CryptoMagic):
    def re_encrypt(self, capsule):
    	return cryptomagic.cryptomagic_get_re_encryption_capsule(self.get_pointer(), capsule.get_pointer())

    def to_bytes(self):
        return cryptomagic.cryptomagic_re_encryption_to_bytes(self.get_pointer())

    def from_bytes(self):
        return cryptomagic.cryptomagic_get_re_encryption_from_bytes(self.get_pointer(), data)

    def free(self):
        cryptomagic.cryptomagic_re_encryption_key_free(self.get_pointer())
