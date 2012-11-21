import random
import string
import unittest

from naivecrypto.crypto.classical import *


ALPHABET = string.ascii_lowercase


class ClassicalCryptoTest(unittest.TestCase):
    """Tests for the module naivecrypto.crypto.classical"""

    def test_shift_cipher(self):
        self.assertEqual('', shift_encrypt(1, ''))
        self.assertEqual('', shift_decrypt(2, ''))
        self.assertEqual('abcde', shift_encrypt(0, 'abcde'))
        self.assertEqual('abcde', shift_decrypt(0, 'abcde'))
        self.assertEqual('cdefg', shift_encrypt(2, 'abcde'))
        self.assertEqual('cdefg', shift_encrypt(28, 'abcde'))
        self.assertEqual('zabcd', shift_encrypt(25, 'abcde'))

    def test_shift_cipher_is_consistent(self):
        for i in range(10):
            key = random.randint(-100, 100)
            length = random.randint(0, 100)
            plaintext = ''.join(random.choice(ALPHABET)
                                for j in range(length))
            ciphertext = shift_encrypt(key, plaintext)
            self.assertEqual(plaintext, shift_decrypt(key, ciphertext))

    def test_shift_cipher_wraps_around_alphabet(self):
        plaintext = 'secret'
        for i in range(10):
            key = random.randint(-100, 100)
            self.assertEqual(shift_encrypt(key, plaintext),
                             shift_encrypt(key % 26, plaintext))

    def test_substitution_cipher(self):
        key = 'fsyhapqojwklnuidxtbrzgcvme'
        self.assertEqual('', substitution_encrypt(key, ''))
        self.assertEqual('', substitution_decrypt(key, ''))
        self.assertEqual(ALPHABET, substitution_encrypt(ALPHABET, ALPHABET))
        self.assertEqual(ALPHABET, substitution_decrypt(key, key))
        self.assertEqual(key, substitution_encrypt(key, ALPHABET))
        self.assertEqual('gatmjnditrfurbaytar',
                         substitution_encrypt(key, 'veryimportantsecret'))
        self.assertEqual('rdobobtzellchsanbwerzp',
                         substitution_decrypt(key, 'thisisreallyobfuscated'))

        self.assertRaises(
            AssertionError, substitution_encrypt, 'abc', ALPHABET)

        self.assertRaises(AssertionError,
                          substitution_decrypt,
                          'aacdefghijklmnopqrstuvwxyz',
                          ALPHABET)

    def test_substitution_cipher_is_consistent(self):
        list_key = list(ALPHABET)
        for i in range(10):
            random.shuffle(list_key)
            key = ''.join(list_key)
            length = random.randint(0, 100)
            plaintext = ''.join(random.choice(ALPHABET)
                                for j in range(length))
            ciphertext = substitution_encrypt(key, plaintext)
            self.assertEqual(plaintext, substitution_decrypt(key, ciphertext))

    def test_vigenere_cipher(self):
        self.assertEqual('', vigenere_encrypt('key', ''))
        self.assertEqual('', vigenere_decrypt('key', ''))
        self.assertEqual('djbcjs', vigenere_encrypt('key', 'secret'))
        self.assertEqual('tellhimaboutme',
                         vigenere_decrypt('cafe', 'wfrqkjsfepaypf'))
        self.assertRaises(AssertionError, vigenere_encrypt, '', 'secret')

    def test_vigenere_cipher_is_consistent(self):
        for i in range(10):
            key_length = random.randint(1, 100)
            plaintext_length = random.randint(0, 100)
            key = ''.join(random.choice(ALPHABET)
                          for j in range(key_length))
            plaintext = ''.join(random.choice(ALPHABET)
                                for j in range(plaintext_length))
            ciphertext = vigenere_encrypt(key, plaintext)
            self.assertEqual(plaintext, vigenere_decrypt(key, ciphertext))
