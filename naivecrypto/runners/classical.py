import random
import string
from collections import namedtuple

from naivecrypto.crypto.classical import (shift_encrypt,
                                          substitution_encrypt,
                                          vigenere_encrypt)


ALPHABET = string.ascii_lowercase

# Path to the dictionary file. Most UNIX systems should have this somewhere.
WORD_FILE_PATH = '/usr/share/dict/words'

# Named tuple to wrap the results of the runners.
RunResult = namedtuple('RunResult', ['key', 'plaintext', 'ciphertext'])


class BaseRunner(object):
    """Base class for classical crypto schemes runners."""

    def __init__(self, encrypt_function, plaintext_length=64, key_length=32):
        self.encrypt_function = encrypt_function
        self.plaintext_length = plaintext_length
        self.key_length = key_length

    def generate_key(self):
        """Generate a random key, using `self.key_length` if it makes sense to
        do so. This method should be implemented by the derived classes.
        """
        raise NotImplementedError

    def generate_plaintext(self):
        """Generate a sentence of `self.plaintext_length` random words from
        the dictionary file (with no space between the words). This is needed
        to have a realistic distribution of letters in the (English) plaintext.

        The algorithm is Waterman's Reservoir Sampling as described in
        section 3.4.2 of Knuth's TAOCP.
        """

        results = []

        with open(WORD_FILE_PATH, 'r') as f:
            for i, line in enumerate(f):
                if i < self.plaintext_length:
                    results.append(line.strip())
                else:
                    r = random.randint(0, i)
                    if r < self.plaintext_length:
                        results[r] = line.strip()

        return ''.join(results)

    def run(self):
        """Generate a ciphertext. The result is wrapped in a RunResult
        namedtuple along with the key and the plaintext used that were used so
        that cracking programs can verify their guesses.
        """

        key = self.generate_key()
        plaintext = self.generate_plaintext()
        ciphertext = self.encrypt_function(key, plaintext)
        return RunResult(key=key, plaintext=plaintext, ciphertext=ciphertext)


class ShiftCipherRunner(BaseRunner):

    def __init__(self, plaintext_length=64):
        super(ShiftCipherRunner, self).__init__(shift_encrypt,
                                                plaintext_length)

    def generate_key(self):
        return random.randint(0, 25)


class SubstitutionCipherRunner(BaseRunner):

    def __init__(self, plaintext_length=64):
        super(SubstitutionCipherRunner, self).__init__(substitution_encrypt,
                                                       plaintext_length)

    def generate_key(self):
        key_list = list(ALPHABET)
        random.shuffle(key_list)
        return ''.join(key_list)


class VigenereCipherRunner(BaseRunner):

    def __init__(self, plaintext_length=64, key_length=32):
        super(VigenereCipherRunner, self).__init__(vigenere_encrypt,
                                                   plaintext_length,
                                                   key_length)

    def generate_key(self):
        return ''.join(random.choice(ALPHABET)
                       for i in range(self.key_length))
