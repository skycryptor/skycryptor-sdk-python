import cryptomagic

class CryptoMagic:
    def __init__(self):
        self.pointer = cryptomagic.cryptomagic_new()

    def clean(self):
        cryptomagic.cryptomagic_clear(self.pointer)

class Key:
    def __init__(self, cm_obj):
        self.pointer = cm.pointer 
        self.cm = cm_obj
