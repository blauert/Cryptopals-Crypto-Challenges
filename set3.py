# https://cryptopals.com/sets/3

import base64
import random

from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter, Padding

from set1_helpers import xor_combination
from set3_helpers import (
    PaddingServerCBC,
    padding_oracle,
    ctr_attack,
    MersenneTwister,
    run_cpp_twister,
    random_time_mersenne,
)


def ch17():
    # https://cryptopals.com/sets/3/challenges/17
    print("17: The CBC padding oracle")
    with open('txt/17.txt') as file:
        lines = [base64.b64decode(line.strip()) for line in file.readlines()]
    cbc = PaddingServerCBC()
    iv, ciphertext = cbc.encrypt_string(random.choice(lines))
    plaintext = padding_oracle(ciphertext, cbc.leaky_decrypt)
    print("Without IV prepended:", Padding.unpad(plaintext, 16).decode('utf-8'))
    plaintext = padding_oracle(iv+ciphertext, cbc.leaky_decrypt)
    print("With IV prepended:", Padding.unpad(plaintext, 16).decode('utf-8'))


def ch18():
    # https://cryptopals.com/sets/3/challenges/18
    print("18: Implement CTR, the stream cipher mode")
    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ctr-mode
    key=b'YELLOW SUBMARINE'
    nonce = 0
    ctr = Counter.new(
        64,  # 64 bit little endian block count (byte count / 16)
        prefix=nonce.to_bytes(8, 'little'),  # 64 bit unsigned little endian nonce
        initial_value=0,
        little_endian=True  # default: big endian!
    )
    ## Encrypt
    e_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    keystream = e_cipher.encrypt(bytearray(64))  # encrypting all zeros reveals the keystream
    print("Keystream:", keystream.hex())
    # Break keystream into blocks and decrypt each block
    block_size = AES.block_size  # 16
    d_cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(keystream), block_size):
        keystream_block = keystream[i:i + block_size]
        decrypted_counter = d_cipher.decrypt(keystream_block)
        print(f"Decrypted counter block {i // block_size}: {decrypted_counter.hex()}")
    # Decrypt
    d_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ct = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    pt = d_cipher.decrypt(ct)
    print(pt.decode('utf-8'))


def ch19():
    # https://cryptopals.com/sets/3/challenges/19
    print("19: Break fixed-nonce CTR mode using substitutions")
    with open('txt/19.txt') as file:
        lines = [base64.b64decode(line.strip()) for line in file.readlines()]
    key=b'YELLOW SUBMARINE'
    nonce = 0
    ctr = Counter.new(
        64,  # 64 bit little endian block count (byte count / 16)
        prefix=nonce.to_bytes(8, 'little'),  # 64 bit unsigned little endian nonce
        initial_value=0,
        little_endian=True  # default: big endian!
    )
    encrypted_lines = []
    for line in lines:
        # In successive encryptions (not in one big running CTR stream), encrypt each line:
        e_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        # Because the CTR nonce wasn't randomized for each encryption,
        # each ciphertext has been encrypted against the same keystream.
        encrypted_lines.append(e_cipher.encrypt(line))
    first_guess, second_guess = ctr_attack(encrypted_lines)
    print(f"{"First guess (letter frequencies):".ljust(39, " ")}Second guess, refined w/ trigrams:")
    print(f"{"".ljust(38, "-")} {"".ljust(38, "-")}")
    for line in encrypted_lines[:5]:
        first = xor_combination(line, first_guess).decode('utf-8')
        second = xor_combination(line, second_guess).decode('utf-8')
        print(f"{first.ljust(39, " ")}{second}")
    print("...")


def ch20():
    # https://cryptopals.com/sets/3/challenges/20
    print("20: Break fixed-nonce CTR statistically")
    with open('txt/20.txt') as file:
        lines = [base64.b64decode(line.strip()) for line in file.readlines()]
    key = get_random_bytes(16)
    nonce = get_random_bytes(8)
    encrypted_lines = []
    for line in lines:
        e_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)  # fixed nonce
        encrypted_lines.append(e_cipher.encrypt(line))
    ## CTR encryption appears different from repeated-key XOR,
    ## but with a fixed nonce they are effectively the same thing
    #shortest_len = min([len(c) for c in encrypted_lines])
    ## truncate them to a common length (the length of the smallest ciphertext will work)
    #truncated_ciphertexts = [c[:shortest_len] for c in encrypted_lines]
    #repeating_key_ciphertexts = bytearray()
    #for c in truncated_ciphertexts:
    #    repeating_key_ciphertexts.extend(c)
    print("Same as challenge 19...")
    first_guess, second_guess = ctr_attack(encrypted_lines)
    for line in encrypted_lines[:5]:
        first = xor_combination(line, first_guess).decode('utf-8')
        second = xor_combination(line, second_guess).decode('utf-8')
        print("Letters:", first)
        print("Refined:", second)
    print("...")


def ch21():
    # https://cryptopals.com/sets/3/challenges/21
    print("21: Implement the MT19937 Mersenne Twister RNG")
    mt = MersenneTwister(seed=1337)
    my_numbers = [mt.randint() for _ in range(9000)]
    print(f"MersenneTwister(seed=1337): 1st: {my_numbers[0]} 9000th: {my_numbers[-1]}")
    cpp_numbers = run_cpp_twister()
    print(f"C++ std::mt19937 mt(1337);: 1st: {cpp_numbers[0]} 9000th: {cpp_numbers[-1]}")


def ch22():
    # https://cryptopals.com/sets/3/challenges/22
    print("22: Crack an MT19937 seed")
    random_number = random_time_mersenne(10, 100)
    print("Starting to guess...")
    cur_time = int(datetime.now().timestamp())
    while True:
        mt = MersenneTwister(seed=cur_time)
        if mt.randint() == random_number:
            print(f"Cracked the seed! It was {cur_time}")
            break
        cur_time -= 1


if __name__ == "__main__":
    ch17(), print()
    ch18(), print()
    ch19(), print()
    ch20(), print()
    ch21(), print()
    ch22(), print()