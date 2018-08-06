#
import cryptomagic
import binascii

#
from .crypto_magic import CryptoMagic
from .public_key import PublicKey
from .re_key import ReEncryptionKey


#
class PrivateKey(CryptoMagic):
    """
    PrivateKey object, which is Python implementation of extended C/C++ library interface
    """

    def __init__(self, cm):
        self.cm = cm
        super().__init__()

    def generate(self):
        """
        Generate Private Key object.

        :param no:
        """
        self.set_pointer(cryptomagic.cryptomagic_generate_private_key(self.get_pointer()))

    def get_public_key(self):
        """
        Get public key from private key

        :param no:
        :return public key:
        """
        pk = PublicKey(CryptoMagic())
        pk.set_pointer(cryptomagic.cryptomagic_get_public_key(self.get_pointer()))
        return pk

    def to_bytes(self):
        """
        Convert Private Key object into byte array

        :return byte array:
        """
        return binascii.hexlify(cryptomagic.cryptomagic_private_key_to_bytes(self.get_pointer()))

    def from_bytes(self, data):
        """
        Get Private Key from given byte array

        :param data: byte array
        """
        self.set_pointer(cryptomagic.cryptomagic_private_key_from_bytes(self.get_pointer(), binascii.unhexlify(data)))

    def generate_re_encryption_key(self, pk):
        """
        Generate ReEncryption key for
        given Public key with our Private key

        :param pk: Public Key obj
        :return rk: generated re-encryption key
        """

        rk = ReEncryptionKey(CryptoMagic())
        rk.set_pointer(cryptomagic.cryptomagic_get_re_encryption_key(self.get_pointer(), pk.get_pointer(), self.cm.get_pointer()))
        return rk

    def decapsulate(self, capsule):
        """
        Decapsulating given capsule and getting back symmetric key

        :param capsule: capsule obj
        :return symmetric key:
        """

        return cryptomagic.cryptomagic_decapsulate(self.cm.get_pointer(), self.get_pointer(), capsule.get_pointer())
