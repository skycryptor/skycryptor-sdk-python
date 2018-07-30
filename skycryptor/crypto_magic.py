import cryptomagic

class CryptoMagic:
    def __init__(self):
        self.__pointer = cryptomagic.cryptomagic_new()

    def get_pointer(self):
        return self.__pointer

    def set_pointer(self, pointer):
        self.__pointer = pointer

    def clear(self):
        cryptomagic.cryptomagic_clear(self.pointer)
