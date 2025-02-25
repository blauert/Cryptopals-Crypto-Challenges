# https://cryptopals.com/sets/2

import base64

from Crypto.Cipher import AES
from Crypto.Util import Padding

from set1_helpers import xor_combination
from set2_helpers import (
    black_box_ecb_cbc,
    encryption_oracle,
    unknown_string_encrypter,
    byte_at_a_time_oracle,
    CookieServer,
    make_admin_profile,
    parse_kv,
    unknown_string_encrypter_harder,
    byte_at_a_time_oracle_harder,
    CookieServerCBC,
    cbc_bit_flip,
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
    decrypted = byte_at_a_time_oracle(enc_func)
    print(decrypted.decode('utf-8'))


def ch13():
    # https://cryptopals.com/sets/2/challenges/13
    print("13: ECB cut-and-paste")
    c = CookieServer()
    print(parse_kv(c.decrypt_profile(c.encrypt_profile('foo@bar.com'))))
    admin_profile = make_admin_profile(c.encrypt_profile)
    print(parse_kv(c.decrypt_profile(admin_profile)))


def ch14():
    # https://cryptopals.com/sets/2/challenges/14
    print("14: Byte-at-a-time ECB decryption (Harder)")
    enc_func = unknown_string_encrypter_harder()
    decrypted = byte_at_a_time_oracle_harder(enc_func)
    print(decrypted.decode('utf-8'))


def ch15():
    # https://cryptopals.com/sets/2/challenges/15
    print("15: PKCS#7 padding validation")
    for string in [b"ICE ICE BABY\x04\x04\x04\x04",
                   b"ICE ICE BABY\x05\x05\x05\x05",
                   b"ICE ICE BABY\x01\x02\x03\x04"]:
        try:
            print(Padding.unpad(string, 16))
        except Exception as e:
            print(e)


def ch16():
    # https://cryptopals.com/sets/2/challenges/16
    print("16: CBC bitflipping attacks")
    c = CookieServerCBC()
    ciphertext = cbc_bit_flip(c.encrypt_string)
    print(c.decrypt_string(ciphertext))
    print(f"-> Is admin? {c.is_admin(ciphertext)}")


if __name__ == "__main__":
    ch9(), print()
    ch10(), print()
    ch11(), print()
    ch12()
    ch13(), print()
    ch14()
    ch15(), print()
    ch16()