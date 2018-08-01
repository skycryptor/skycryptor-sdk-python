#
from .crypto_magic import CryptoMagic
from .private_key import PrivateKey
from .public_key import PublicKey
from .capsule import Capsule
from .re_key import ReEncryptionKey


#
class SkyCryptor(CryptoMagic):
    """
    Main Skycryptor structure for having API functions referenced from it.
    """

    def generate(self):
        """
        Generate Private Key

        :param no
        :return private key:
        """
        sk = PrivateKey(CryptoMagic())
        sk.generate()
        return sk

    def private_key_from_bytes(self, data):
        """
        Get private key from given byte array.

        :param data: byte array
        :return: private key
        """
        sk = PrivateKey(CryptoMagic())
        sk.set_pointer(self.get_pointer())
        sk.from_bytes(data)
        return sk

    def public_key_from_bytes(self, data):
        """
        Get public key from given byte array.

        :param data: byte array
        :return: public key
        """
        pk = PublicKey(CryptoMagic())
        pk.set_pointer(self.get_pointer())
        pk.from_bytes(data)
        return pk

    def capsule_from_bytes(self, data):
        """
        Get capsule key from given byte array.

        :param data: byte array
        :return: capsule
        """
        cs = Capsule()
        cs.set_pointer(self.get_pointer())
        cs.from_bytes(data)
        return cs

    def re_encryption_key_from_bytes(self, data):
        """
        Get re-encryption key from given byte array.

        :param data: byte array
        :return: re-encryption key
        """
        rk = ReEncryptionKey()
        rk.set_pointer(self.get_pointer())
        rk.from_bytes(data)
        return rk
