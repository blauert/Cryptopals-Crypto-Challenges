# https://cryptopals.com/sets/1

import base64
import binascii
import codecs

from Crypto.Cipher import AES

from helpers import (
    xor_combination,
    decypher_single_byte_xor,
    repeating_key_xor,
    guess_keysize,
    break_vigenere_key,
)


def ch1():
    # https://cryptopals.com/sets/1/challenges/1
    print("1: Convert hex to base64")
    bytes_str = bytes.fromhex('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    print(bytes_str)
    print(base64.b64encode(bytes_str))


def ch2():
    # https://cryptopals.com/sets/1/challenges/2
    print("2: Fixed XOR")
    buf1, buf2 = bytes.fromhex('1c0111001f010100061a024b53535009181c'), bytes.fromhex('686974207468652062756c6c277320657965')
    result = xor_combination(buf1, buf2)
    print(result)
    print(binascii.hexlify(result))


def ch3():
    # https://cryptopals.com/sets/1/challenges/3
    print("3: Single-byte XOR cipher")
    string = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    _, _, result = decypher_single_byte_xor(string)
    print(result)


def ch4():
    # https://cryptopals.com/sets/1/challenges/4
    print("4: Detect single-character XOR")
    with open('txt/4.txt') as file:
        lines = [bytes.fromhex(line) for line in file.readlines()]
    scores = []
    for line in lines:
        scores.append(decypher_single_byte_xor(line))
    scores.sort()
    _, _, result = scores[0]
    print(result)


def ch5():
    # https://cryptopals.com/sets/1/challenges/5
    print("5: Implement repeating-key XOR")
    stanza = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b'ICE'
    print(stanza)
    result = repeating_key_xor(stanza, key)
    print(binascii.hexlify(result))


def ch6():
    # https://cryptopals.com/sets/1/challenges/6
    print("6: Break repeating-key XOR")
    with open('txt/6.txt') as file:
        ciphertext = base64.b64decode(file.read())
    keysize = guess_keysize(ciphertext)
    key = break_vigenere_key(ciphertext, keysize)
    print(key)
    plaintext = repeating_key_xor(ciphertext, key)
    print(plaintext.decode('utf-8', errors='ignore')[:220], "...")


def ch7():
    # https://cryptopals.com/sets/1/challenges/7
    print("7: AES in ECB mode")
    key = b"YELLOW SUBMARINE"
    with open('txt/7.txt') as file:
        ciphertext = base64.b64decode(file.read())
    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ecb-mode
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext.decode('utf-8', errors='ignore')[:220], "...")


def ch8():
    # https://cryptopals.com/sets/1/challenges/8
    print("8: Detect AES in ECB mode")
    with open('txt/8.txt') as file:
        lines = [bytes.fromhex(line.strip()) for line in file.readlines()]
    ecb_candidates = []
    for line_num, line in enumerate(lines):
        line_num+=1 # match actual line numbers starting from 1
        # split into 16-byte blocks
        blocks = [line[i:i+16] for i in range(0, len(line), 16)]
        num_repeated_blocks = len(blocks) - len(set(blocks))
        ecb_candidates.append((num_repeated_blocks, line_num, line))
    ecb_candidates.sort()
    res = ecb_candidates[-1]
    print(f"{res[0]} repeating blocks in line {res[1]}: {codecs.encode(res[2], 'hex')}")


if __name__ == "__main__":
    ch1(), print()
    ch2(), print()
    ch3(), print()
    ch4(), print()
    ch5(), print()
    ch6(), print()
    ch7(), print()
    ch8()