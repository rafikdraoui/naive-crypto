# -*- coding: utf-8 -*-

from naivecrypto.runners.classical import VigenereCipherRunner


class VigenereCracker(object):
    """The Kasiski attack on the Vigenère cipher."""

    runner = VigenereCipherRunner

    #TODO
    def crack(self):
        pass
