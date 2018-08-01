#
import cryptomagic


#
class CryptoMagic:
    """
    Main Crypto operations structure, which is a Python implementation
    of existing C/C++ library interface
    """

    def __init__(self):
        """
        Making new CryptoMagic root object to perform cryptographic operations.

        :param no:
        """
        self.__pointer = cryptomagic.cryptomagic_new()

    def get_pointer(self):
        return self.__pointer

    def set_pointer(self, pointer):
        self.__pointer = pointer
