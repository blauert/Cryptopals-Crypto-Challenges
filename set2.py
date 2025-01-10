# https://cryptopals.com/sets/2

from Crypto.Util import Padding


def ch9():
    # https://cryptopals.com/sets/2/challenges/9
    print("9: Implement PKCS#7 padding")
    key = b"YELLOW SUBMARINE"
    block_size = 20
    # https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#module-Crypto.Util.Padding
    print(Padding.pad(key, block_size, 'pkcs7'))


def ch10():
    # https://cryptopals.com/sets/2/challenges/10
    print("10: Implement CBC mode")
    # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
    pass


if __name__ == "__main__":
    ch9(), print()