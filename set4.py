# https://cryptopals.com/sets/4

import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

from set1_helpers import xor_combination

from set4_helpers import (
    exposed_edit,
    CookieServerCTR,
    ctr_bit_flip,
)



def ch25():
    # https://cryptopals.com/sets/4/challenges/25
    print('25: Break "random access read/write" AES CTR')
    with open('txt/25.txt') as file:
        ciphertext = base64.b64decode(file.read())
    cipher = AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB)
    plaintext = Padding.unpad(cipher.decrypt(ciphertext), 16)
    # Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key
    key = get_random_bytes(16)
    fixed_nonce = int(0).to_bytes(8)
    e_cipher = AES.new(key, AES.MODE_CTR, nonce=fixed_nonce)
    ctext = e_cipher.encrypt(plaintext)
    # the attacker has the ciphertext and controls the offset and "new text"
    keystream = exposed_edit(ctext, key, 0, b'\x00'*len(ctext))
    # Recover the original plaintext
    plaintext = xor_combination(ctext, keystream)
    print(plaintext[:81])


def ch26():
    # https://cryptopals.com/sets/4/challenges/26
    print("26: CTR bitflipping")
    c = CookieServerCTR()
    print(f"Is admin? -> {c.is_admin(ctr_bit_flip(c.encrypt_string))}")


if __name__ == "__main__":
    ch25(), print()
    ch26(), print()