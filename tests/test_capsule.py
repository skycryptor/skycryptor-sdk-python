#
import os
path = os.environ["package"]
os.sys.path.append(path)
from os.path import dirname, abspath

import base64
import binascii
from Crypto.Cipher import AES


#
from cryptomagic_test import TestCryptoMagic

#
import binascii
from skycryptor.skycryptor import SkyCryptor


#
class AESCipher(object):
    def __init__(self, key):
        self.bs = 16
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, raw):
        raw = self._pad(raw)
        encrypted = self.cipher.encrypt(raw)
        encoded = base64.b64encode(encrypted)
        return str(encoded, 'utf-8')

    def decrypt(self, raw):
        decoded = base64.b64decode(raw)
        decrypted = self.cipher.decrypt(decoded)
        return str(self._unpad(decrypted), 'utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]


#
class Capsule(TestCryptoMagic):
    #
    def setUp(self):
        super(Capsule, self).setUp()

    #
    def test_capsule_from_to_bytes(self):
        sc = SkyCryptor()
        sk = sc.generate()
        pk = sk.get_public_key()

        capsule_1, _ = pk.encapsulate()
        cData_1 = capsule_1.to_bytes()
        capsule_2 = sc.capsule_from_bytes(cData_1)
        cData_2 = capsule_2.to_bytes()

        self.assertEqual(cData_1, cData_2)

    def test_encapsulate_decapsulate(self):
        sc = SkyCryptor()
        sk = sc.generate()
        pk = sk.get_public_key()

        capsule_1, sym_key_1 = pk.encapsulate()
        cData_1 = capsule_1.to_bytes()

        capsule_2 = sc.capsule_from_bytes(cData_1)
        cData_2 = capsule_2.to_bytes()

        self.assertEqual(cData_1, cData_2)

    def test_AES_encrypt_decrypt(self):
        sc = SkyCryptor()
        alice_sk = sc.generate()
        alice_pk = alice_sk.get_public_key()

        bob_sk = sc.generate()
        bob_pk = bob_sk.get_public_key()

        capsule, symmetric_key_1 = bob_pk.encapsulate()

        alice_cipher = AESCipher(binascii.hexlify(symmetric_key_1)[:16])

        plaintext = 'abkcdcln;lfwenhcbehkslascn.osbo'
        encrypted = alice_cipher.encrypt(plaintext)

        symmetric_key_2 = bob_sk.decapsulate(capsule)
        bob_cipher = AESCipher(binascii.hexlify(symmetric_key_2)[:16])

        decrypted = bob_cipher.decrypt(encrypted)

        self.assertEqual(decrypted, plaintext)

    def test_AES_encrypt_decrypt_re_encrypt(self):
        sc = SkyCryptor()

        # create private, public keys
        alice_sk = sc.generate()
        alice_pk = alice_sk.get_public_key()
        bob_sk = sc.generate()
        bob_pk = bob_sk.get_public_key()

        alice_capsule, alice_symmetric_key = alice_pk.encapsulate()

        rk_AB = alice_sk.generate_re_encryption_key(bob_pk)
 
        alice_cipher = AESCipher(binascii.hexlify(alice_symmetric_key)[:16])

        plaintext = 'abkcdclnlfwenhcbehkslascnosbo'
        ciphertext = alice_cipher.encrypt(plaintext)

        recapsule = rk_AB.re_encrypt(alice_capsule)

        bob_symmetric_key = bob_sk.decapsulate(recapsule)
        bob_cipher = AESCipher(binascii.hexlify(bob_symmetric_key)[:16])
       
        decrypted = bob_cipher.decrypt(ciphertext)

        self.assertEqual(binascii.hexlify(alice_symmetric_key), binascii.hexlify(bob_symmetric_key))
        self.assertEqual(decrypted, plaintext)
