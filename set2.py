# https://cryptopals.com/sets/2

import base64

from Crypto.Cipher import AES
from Crypto.Util import Padding

from set1_helpers import xor_combination
from set2_helpers import (
    black_box_ecb_cbc,
    encryption_oracle,
    unknown_string_encrypter,
    detect_block_size,
    detect_ecb,
    byte_at_a_time_oracle,
    CookieServer,
    make_admin_profile,
    parse_kv,
)


def ch9():
    # https://cryptopals.com/sets/2/challenges/9
    print("9: Implement PKCS#7 padding")
    message = b"YELLOW SUBMARINE"
    block_size = 20
    # https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#module-Crypto.Util.Padding
    print(Padding.pad(message, block_size, 'pkcs7'))


def ch10():
    # https://cryptopals.com/sets/2/challenges/10
    print("10: Implement CBC mode")
    with open('txt/10.txt') as file:
        ciphertext = base64.b64decode(file.read())
    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key, AES.MODE_ECB)
    print("Key:", key)
    block_size = 16  # AES.block_size
    iv = b'\x00' * block_size  # initialization vector
    print("IV:", iv)
    # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
    plaintext = bytearray()
    prev_block = iv
    for i in range(0, len(ciphertext), block_size):
        encrypted_block = ciphertext[i:i + block_size]
        plaintext.extend(xor_combination(prev_block, cipher.decrypt(encrypted_block)))
        prev_block = encrypted_block
    # remove pkcs7 padding
    last_2_blocks = int((len(plaintext)/block_size-2)*block_size)
    print("Original:", plaintext[last_2_blocks:])
    plaintext = Padding.unpad(plaintext, block_size)
    print("Unpadded:", plaintext[last_2_blocks:])
    print(plaintext.decode('utf-8')[:220], "...")


def ch11():
    # https://cryptopals.com/sets/2/challenges/11
    print("11: An ECB/CBC detection oracle")
    ecb_detected = False
    cbc_detected = False
    while not (ecb_detected and cbc_detected):
        mode = encryption_oracle(black_box_ecb_cbc(b'BLA'*100))
        match mode:
            case 'ECB': ecb_detected = True
            case 'CBC': cbc_detected = True


def ch12():
    # https://cryptopals.com/sets/2/challenges/12
    print("12: Byte-at-a-time ECB decryption (Simple)")
    enc_func = unknown_string_encrypter()
    block_size = detect_block_size(enc_func)
    print(f"Block size: {block_size}")
    ecb = detect_ecb(enc_func, block_size)
    print(f"ECB detected: {ecb}")
    decrypted = byte_at_a_time_oracle(enc_func, block_size)
    print(decrypted.decode('utf-8'))


def ch13():
    # https://cryptopals.com/sets/2/challenges/13
    print("13: ECB cut-and-paste")
    c = CookieServer()
    print(parse_kv(c.decrypt_profile(c.encrypt_profile('foo@bar.com'))))
    admin_profile = make_admin_profile(c.encrypt_profile)
    print(parse_kv(c.decrypt_profile(admin_profile)))


if __name__ == "__main__":
    ch9(), print()
    ch10(), print()
    ch11(), print()
    ch12()
    ch13(), print()