from __future__ import division

import string
from collections import Counter

from naivecrypto.crypto.classical import shift_decrypt
from naivecrypto.runners.classical import (ShiftCipherRunner,
                                           SubstitutionCipherRunner)


ALPHABET = string.ascii_lowercase

# Average letter frequencies for English-language text.
FREQUENCIES = [8.2, 1.5, 2.8, 4.2, 12.7, 2.2, 2.0, 6.1, 7.0, 0.1, 0.8, 4.0,
               2.4, 6.7, 7.5, 1.9, 0.1, 6.0, 6.3, 9.0, 2.8, 1.0, 2.4, 0.1,
               2.0, 0.1]


def _chi_square(observed, expected):
    """Returned the chi square value of the two given sequences."""
    f = lambda o, e: pow(o - e, 2) / e
    return sum(map(f, observed, expected))


def _rotate(n, seq):
    """Rotate to the right the sequence by `n` steps (with wrap-around)."""
    return seq[n:] + seq[:n]


class ShiftCracker(object):
    """A cracker for the shift cipher. It uses frequency analysis on the
    letters of the ciphertext to guess the shift key.
    """

    runner = ShiftCipherRunner

    def crack(self, ciphertext):
        # make frequency table of the letters in ciphertext
        counter = Counter(ciphertext)
        freq_table = [counter.get(c, 0) / len(ciphertext) for c in ALPHABET]

        chis = (_chi_square(_rotate(i, freq_table), FREQUENCIES)
                for i in range(len(ALPHABET)))

        # the key is the index of the minimum chi-square value
        key = sorted(enumerate(chis), key=lambda pair: pair[-1])[0][0]

        return key, shift_decrypt(key, ciphertext)


class SubstitutionCracker(object):
    runner = SubstitutionCipherRunner

    #TODO
    def crack(self, ciphertext):
        pass


def exercise_cracker(cracker, num_runs):
    """Run the given cracker on `num_runs` instance of its runner, and check
    if the guesses are correct. Return a pair (success, failure) giving the
    number of successful and failed guesses.
    """

    success, failure = 0, 0
    runner = cracker.runner()
    for i in range(num_runs):
        result = runner.run()
        key, plaintext = cracker.crack(result.ciphertext)
        if key == result.key and plaintext == result.plaintext:
            success += 1
        else:
            failure += 1
    return success, failure


if __name__ == '__main__':
    print('Success: %d\nFailure: %d' % exercise_cracker(ShiftCracker(), 5))
