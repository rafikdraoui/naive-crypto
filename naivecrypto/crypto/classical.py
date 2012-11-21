# -*- coding: utf-8 -*-

"""Some classical cryptographic schemes. In all the following, the alphabet
consists of the lowercase ASCII letters.
"""

import string
from itertools import cycle, izip
from operator import add, sub


__all__ = ['shift_encrypt', 'shift_decrypt', 'substitution_encrypt',
           'substitution_decrypt', 'vigenere_encrypt', 'vigenere_decrypt']

ALPHABET = string.ascii_lowercase


#-- Shift (aka Caesar) cipher --#

# The key is an integer.

def shift_encrypt(key, plaintext):
    n = key % 26
    subst_key = ALPHABET[n:] + ALPHABET[:n]
    return substitution_encrypt(subst_key, plaintext)


def shift_decrypt(key, ciphertext):
    return shift_encrypt(-key, ciphertext)


#-- Mono-alphabetic substitution cipher --#

# The key is a string consisting of a permutation of the alphabet.

def substitution_encrypt(key, plaintext):
    assert len(key) == len(ALPHABET), \
        'Substitution key must have the same length as the alphabet'

    assert len(set(key)) == len(ALPHABET), \
        'Substitution key must be a permutation, i.e. no repeat letter'

    subst = string.maketrans(ALPHABET, key)
    return plaintext.translate(subst)


def substitution_decrypt(key, ciphertext):
    assert len(key) == len(ALPHABET), \
        'Substitution key must have the same length as the alphabet'

    assert len(set(key)) == len(ALPHABET), \
        'Substitution key must be a permutation, i.e. no repeat letter'

    subst = string.maketrans(key, ALPHABET)
    return ciphertext.translate(subst)


#-- Vigenère cipher --#

# The key is a string.

def _combine_letters(op, x, y):
    """Combine two letters `x` and `y` according to the operation `op` on
    their indices in the alphabet, wrapping around the alphabet.
    """
    new_index = op(ALPHABET.index(x), ALPHABET.index(y) + 1) % len(ALPHABET)
    return ALPHABET[new_index]


def vigenere_encrypt(key, plaintext):
    assert len(key) > 0, 'Empty key'

    result = (_combine_letters(add, x, y)
              for x, y in izip(plaintext, cycle(key)))
    return ''.join(result)


def vigenere_decrypt(key, ciphertext):
    assert len(key) > 0, 'Empty key'

    result = (_combine_letters(sub, x, y)
              for x, y in izip(ciphertext, cycle(key)))
    return ''.join(result)
