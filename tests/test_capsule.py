#
import os

import base64
from Crypto.Cipher import AES


#
from proxylib_test import TestProxyLib

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
        encrypted = self.cipher.encrypt(raw.encode("latin-1"))
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
class Capsule(TestProxyLib):
    #
    def setUp(self):
        super(Capsule, self).setUp()

    #
    def test_capsule_from_to_bytes(self):
        Skycryptor = SkyCryptor()
        sk = Skycryptor.generate()
        pk = Skycryptor.public_key(sk)

        capsule_1, _ = Skycryptor.encapsulate(pk)
        cData_1 = capsule_1.to_bytes()
        capsule_2 = Skycryptor.capsule_from_bytes(cData_1)
        cData_2 = capsule_2.to_bytes()

        self.assertEqual(cData_1, cData_2)

    def test_encapsulate_decapsulate(self):
        Skycryptor = SkyCryptor()
        sk = Skycryptor.generate()
        pk = Skycryptor.public_key(sk)

        capsule_1, sym_key_1 = Skycryptor.encapsulate(pk)
        cData_1 = capsule_1.to_bytes()

        capsule_2 = Skycryptor.capsule_from_bytes(cData_1)
        cData_2 = capsule_2.to_bytes()

        self.assertEqual(cData_1, cData_2)

    def test_AES_encrypt_decrypt(self):
        Skycryptor = SkyCryptor()
        alice_sk = Skycryptor.generate()
        alice_pk = Skycryptor.public_key(alice_sk)

        bob_sk = Skycryptor.generate()
        bob_pk = Skycryptor.public_key(bob_sk)

        capsule, symmetric_key_1 = Skycryptor.encapsulate(bob_pk)
        #print("\n{}\n".format(binascii.hexlify(symmetric_key_1)))
        alice_cipher = AESCipher(binascii.hexlify(symmetric_key_1)[:16])

        plaintext = 'abkcdclnlfwenhcbehkslaSkycryptornosbo'
        encrypted = alice_cipher.encrypt(plaintext)

        symmetric_key_2 = Skycryptor.decapsulate(bob_sk, capsule)
        bob_cipher = AESCipher(binascii.hexlify(symmetric_key_2)[:16])

        decrypted = bob_cipher.decrypt(encrypted)

        self.assertEqual(decrypted, plaintext)

    def test_AES_encrypt_decrypt_re_encrypt(self):
        Skycryptor = SkyCryptor()

        # create private, public keys
        alice_sk = Skycryptor.generate()
        alice_pk = Skycryptor.public_key(alice_sk)

        bob_sk = Skycryptor.generate()
        bob_pk = Skycryptor.public_key(bob_sk)

        # re-encryption key from Alice to Bob
        rk_AB = Skycryptor.generate_re_key(alice_sk, bob_pk)

        # alice encrypt plaintext
        alice_capsule, alice_symmetric_key = Skycryptor.encapsulate(alice_pk)
        print("\n{}\n".format(binascii.hexlify(alice_symmetric_key)))
        alice_cipher = AESCipher(binascii.hexlify(alice_symmetric_key)[:16])
        plaintext = 'abkcdclnlfwenhcbehkslascnosbo'
        ciphertext = alice_cipher.encrypt(plaintext)
        # Bob decrypt ciphertext

        # first re-encrypt capsule
        recapsule = Skycryptor.re_encrypt(rk_AB, alice_capsule)
        bob_symmetric_key = Skycryptor.decapsulate(bob_sk, recapsule)

        recapsule = rk_AB.re_encrypt(alice_capsule)

        bob_symmetric_key = bob_sk.decapsulate(recapsule)
        bob_cipher = AESCipher(binascii.hexlify(bob_symmetric_key)[:16])
       
        decrypted = bob_cipher.decrypt(ciphertext)

        self.assertEqual(binascii.hexlify(alice_symmetric_key), binascii.hexlify(bob_symmetric_key))
