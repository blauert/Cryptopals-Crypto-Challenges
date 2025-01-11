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


if __name__ == "__main__":
    # Oracle
    print("Black box:", black_box_ecb_cbc(b'X'*50))

