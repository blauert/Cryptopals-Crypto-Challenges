import base64
import random

from Crypto.Cipher import AES
from Crypto.Util import Padding


def black_box_ecb_cbc(plaintext):
    key_size = 16
    block_size = 16
    # append 5-10 bytes (count chosen randomly) before the plaintext
    pre_bytes = random.randbytes(random.randint(5, 10))
    # and 5-10 bytes after the plaintext
    post_bytes = random.randbytes(random.randint(5, 10))
    plaintext_randbytes = pre_bytes + plaintext + post_bytes
    # apply padding
    plaintext_padded = Padding.pad(plaintext_randbytes, block_size)
    # generate a random AES key; that's just 16 random bytes
    key = random.randbytes(key_size)
    mode = random.choice(['ECB', 'CBC'])
    print(f"Encryption mode: {mode}")
    match mode:
        case 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
        case 'CBC':
            iv = random.randbytes(block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(plaintext_padded)
    return ciphertext


def encryption_oracle(ciphertext):
    block_size = 16
    blocks = set()
    block_count = 0
    # ignore first and last block (distorted by random bytes)
    for i in range(block_size, len(ciphertext)-block_size, block_size):
        cur_block = ciphertext[i:i + block_size]
        blocks.add(cur_block)
        block_count += 1
    repeated_blocks = block_count - len(blocks)
    if repeated_blocks != 0:
        mode = 'ECB'
        print(f'{repeated_blocks} repeated blocks -> ECB detected!')
    else:
        mode = 'CBC'
        print('No repeated blocks -> CBC detected!')
    return mode


def unknown_string_encrypter():
    with open('txt/12.txt') as file:
        unknown_string = base64.b64decode(file.read())
    key = random.randbytes(16)
    cipher = AES.new(key, AES.MODE_ECB)

    def encrypt_func(my_string):
        my_string += unknown_string
        return cipher.encrypt(Padding.pad(my_string, 16))
    
    return encrypt_func


def detect_block_size(enc_func):
    # Discover the block size of the cipher.
    start_len = len(enc_func(b'A'))
    i = 2
    while True:
        cur_len = len(enc_func(b'A' * i))
        if cur_len > start_len:
            break
        i += 1
    return cur_len - start_len


def detect_ecb(enc_func, block_size):
    # Detect that the function is using ECB.
    my_input = b'A' * block_size * 10
    blocks = set()
    block_count = 0
    ciphertext = enc_func(my_input)
    for i in range(0, len(ciphertext), block_size):
        cur_block = ciphertext[i:i + block_size]
        blocks.add(cur_block)
        block_count += 1
    repeated_blocks = block_count - len(blocks)
    if repeated_blocks != 0:
        return True
    else:
        return False


def number_of_As(plaintext, block_size):
    return len(plaintext) // block_size * block_size + block_size - len(plaintext)


def byte_at_a_time_oracle(enc_func, block_size):
    plaintext = bytearray(b'')
    byte_idx = block_size  # start at last byte in block
    while True:
        i = (len(plaintext) // block_size) * block_size
        # input block that is exactly 1 byte short
        known_input = b'A' * (number_of_As(plaintext, block_size) - 1)
        cur_block = enc_func(known_input)[i:i+block_size]
        # try every possible last byte
        decrypted = False
        for ascii_char in range(128):
            cur_char = chr(ascii_char).encode()
            cur_input = known_input + plaintext + cur_char
            if enc_func(cur_input)[i:i+block_size] == cur_block:
                plaintext.extend(cur_char)
                decrypted = True
                break
        if not decrypted:
            break
        byte_idx -= 1
        if byte_idx == 0:
            byte_idx = block_size
    # fill up to match block_size and remove padding
    fillers = number_of_As(plaintext, block_size)
    unpadded = Padding.unpad(b'A' * fillers + plaintext, block_size)
    return unpadded[fillers:]


if __name__ == "__main__":
    # Oracle
    print("Black box:", black_box_ecb_cbc(b'X'*50))
    print()
    # Prepend As
    for i in [3, 15, 16, 35]:
        text = i * 'B'
        output = (number_of_As(text, 16) - 1) * 'A' + text
        print(output, len(output), f"({i}xB)")