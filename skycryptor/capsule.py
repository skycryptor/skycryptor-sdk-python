#
import binascii
import cryptomagic

#
from .crypto_magic import CryptoMagic


#
class Capsule(CryptoMagic):
    """
    Cryptographic capsule referenced from C/C++ library implementation.
    """

    def to_bytes(self):
        """
        Convert Capsule object into byte array

        :param no:
        :return byte array:
        """
        return binascii.hexlify(cryptomagic.cryptomagic_capsule_to_bytes(self.get_pointer()))

    def from_bytes(self, data):
        """
        Get capsule key from given byte array.

        :param data: byte array
        :return: no
        """

        self.set_pointer(cryptomagic.cryptomagic_capsule_from_bytes(self.get_pointer(), binascii.unhexlify(data)))
