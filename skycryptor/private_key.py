import cryptomagic

from crypto_magic import CryptoMagic
from public_key import PublicKey

class PrivateKey(CryptoMagic):
    def generate(self):
        self.set_pointer(cryptomagic.cryptomagic_generate_private_key(self.get_pointer()))

    def get_public_key(self):
        pk = PublicKey()
        pk.set_pointer(cryptomagic.cryptomagic_get_public_key(self.get_pointer()))
        return pk

    def to_bytes(self):
        return cryptomagic.cryptomagic_private_key_to_bytes(self.get_pointer())

    def from_bytes(self, data):
        return cryptomagic.cryptomagic_private_key_from_bytes(self.get_pointer(), data)

    def generate_re_encryption_key(self, pk):
        return cryptomagic.cryptomagic_get_re_encryption_key(self.get_pointer(), pk.get_pointer())

    def decapsulate(self, capsule):
        cm = CryptoMagic()
        cm.set_pointer(self.get_pointer())
        return cryptomagic.cryptomagic_decapsulate(cm.get_pointer(),self.get_pointer(), capsule.get_pointer())

    def free(self):
        cryptomagic.cryptomagic_private_key_free(self.get_pointer())
