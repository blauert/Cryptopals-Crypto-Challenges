# https://cryptopals.com/sets/3

import base64
import random

from Crypto.Util import Padding

from set3_helpers import (
    PaddingServerCBC,
    padding_oracle,
)


def ch17():
    # https://cryptopals.com/sets/3/challenges/17
    print("17: The CBC padding oracle")
    with open('txt/17.txt') as file:
        lines = [line.strip().encode() for line in file.readlines()]
    cbc = PaddingServerCBC()
    iv, ciphertext = cbc.encrypt_string(random.choice(lines))
    plaintext = padding_oracle(ciphertext, cbc.leaky_decrypt)
    print("Without IV prepended:", base64.b64decode(Padding.unpad(plaintext, 16)))
    plaintext = padding_oracle(iv+ciphertext, cbc.leaky_decrypt)
    print("With IV prepended:", base64.b64decode(Padding.unpad(plaintext, 16)))


if __name__ == "__main__":
    ch17(), print()
    