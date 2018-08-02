#
import binascii
import cryptomagic

#
from .crypto_magic import CryptoMagic


#
class ReEncryptionKey(CryptoMagic):
    def re_encrypt(self, capsule):
        """
        Running re-encryption for given capsule and returning re-encrypted capsule

        :param capsule: capsule obj
        :return recapsule: re-encrypted capsule
        """

        recapsule = cryptomagic.cryptomagic_get_re_encryption_capsule(self.get_pointer(), capsule.get_pointer())
        return recapsule

    def to_bytes(self):
        """
        Convert Re-Encryption Key object into byte array

        :param no:
        :return byte array:
        """

        return binascii.hexlify(cryptomagic.cryptomagic_re_encryption_to_bytes(self.get_pointer()))

    def from_bytes(self, data):
        """
        Get Re-Encryption key from given byte array.

        :param data: byte array
        :return: no
        """

        self.set_pointer(cryptomagic.cryptomagic_get_re_encryption_from_bytes(self.get_pointer(), binascii.unhexlify(data)))
