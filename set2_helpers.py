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


def byte_at_a_time_oracle(enc_func):
    block_size = detect_block_size(enc_func)
    if not detect_ecb(enc_func, block_size):
        return
    plaintext = bytearray(b'')
    byte_idx = block_size  # start at last byte in block
    while True:
        # block index (starting at 0)
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


def parse_kv(cookie):
    data = {}
    for pair in cookie.split('&'):
        k, v = pair.split('=')
        data[k] = v
    return data


def profile_for(email):
    return f"email={email.replace('&', '').replace('=', '')}&uid=10&role=user"


class CookieServer:
    
    def __init__(self):
        self.block_size = 16
        self.cipher = AES.new(random.randbytes(16), AES.MODE_ECB)

    def encrypt_profile(self, email):
        if type(email) == bytes:  # allow detect_block_size() to input bytes
            email = email.decode()
        profile = profile_for(email)
        return self.cipher.encrypt(Padding.pad(profile.encode(), self.block_size))

    def decrypt_profile(self, ciphertext):
        return Padding.unpad(self.cipher.decrypt(ciphertext), self.block_size).decode()


def make_admin_profile(enc_func):
    block_size = detect_block_size(enc_func)
    if not detect_ecb(enc_func, block_size):
        return

    first_part = 'email='
    middle_part = '&uid=10&role='

    # email=xx1337h@ck .er&uid=10&role= user
    filler_email = '1337h@ck.er'.rjust((2 * block_size - len(first_part) - len(middle_part)), 'x')
    # email=xx1337h@xX .0r&uid=10&role=
    email_and_role_block = enc_func(filler_email)[:2*block_size]

    # email=AAAAAAAAAA admin&uid=10&rol e=user
    evil_email = (block_size - len(first_part)) * 'A' + 'admin'
    # admin&uid=10&rol
    admin_block = enc_func(evil_email)[block_size:2*block_size]

    # email=AAAAAAAAAA AAAA&uid=10&role =user
    filler_end = 'A' * (2*block_size - len(first_part) - len(middle_part) + 1)
    # =user
    last_block = enc_func(filler_end)[2*block_size:3*block_size]

    # email=xx1337h@xX .0r&uid=10&role= admin&uid=10&rol =user
    return email_and_role_block + admin_block + last_block


def unknown_string_encrypter_harder():
    # AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    with open('txt/12.txt') as file:
        unknown_string = base64.b64decode(file.read())
    key = random.randbytes(16)
    cipher = AES.new(key, AES.MODE_ECB)

    random_bytes = random.randbytes(random.randint(0,100))
    print(f"Length of random prefix: {len(random_bytes)}")

    def encrypt_func(my_string):
        my_string = random_bytes + my_string + unknown_string
        return cipher.encrypt(Padding.pad(my_string, 16))
    
    return encrypt_func


def detect_target_start(enc_func):
    block_size = detect_block_size(enc_func)
    if not detect_ecb(enc_func, block_size):
        return
    # detect start of the target bytes
    input_len = 2 * block_size
    target_start = None
    while True:
        my_input = b'A' * input_len
        ciphertext = enc_func(my_input)
        for i in range(block_size, len(ciphertext), block_size):
            prev_block = ciphertext[i-block_size:i]
            cur_block = ciphertext[i:i+block_size]
            # break as soon as my_input generates two identical blocks
            if cur_block == prev_block:
                # target starts at length of random prefix
                target_start = i-block_size - (input_len % block_size)
                break
        if target_start is not None:
            break
        input_len += 1
    return block_size, target_start


def byte_at_a_time_oracle_harder(enc_func):
    """
    fill up the last prefix block with A's
              v
    PPPPAAAAAAAAAAAA AAAAAAAAAAAAAAAT TTTTTTTTTTTTTTTT
                            ^
    the first block after last prefix block is where it's at
    
    -> same as ch12, just add target_start & prefix_fillers to everything
    """
    block_size, target_start = detect_target_start(enc_func)
    print(f'Target bytes start at index: {target_start}')
    # bytes in target block occupied by prefix
    prefix_fillers = block_size - (target_start % block_size)
    print(f"Start configuration: {'P' * (block_size - prefix_fillers)}{'A' * (prefix_fillers)} {'A' * 15}T")
    # decrypt the target-bytes
    plaintext = bytearray(b'')
    byte_idx = block_size  # start at last byte in block
    while True:
        # block index (starting at 0)
        i = (((len(plaintext) // block_size)) + (target_start + prefix_fillers) // block_size) * block_size
        # input block that is exactly 1 byte short
        known_input = b'A' * (number_of_As(plaintext, block_size) + prefix_fillers - 1)
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


class CookieServerCBC:
    
    def __init__(self):
        self.block_size = 16
        key = random.randbytes(16)
        iv = random.randbytes(self.block_size)
        self.e_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        self.d_cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    def encrypt_string(self, user_input):
        user_input = user_input.replace(';', '";"').replace('=', '"="')
        new_string = f"comment1=cooking%20MCs;userdata={user_input};comment2=%20like%20a%20pound%20of%20bacon"
        return self.e_cipher.encrypt(Padding.pad(new_string.encode(), self.block_size))

    def decrypt_string(self, ciphertext):
        return Padding.unpad(self.d_cipher.decrypt(ciphertext), self.block_size)
    
    def is_admin(self, ciphertext):
        plaintext = self.decrypt_string(ciphertext).decode(errors='ignore')
        if ";admin=true;" in plaintext:
            return True
        else:
            return False


def cbc_bit_flip(enc_func):
    # index           16               32               48
    #                                   bit flip here    sets bit here
    #                                   v                v
    # comment1=cooking %20MCs;userdata= AAAAAAAAAAAAAAAA AadminAtrue;comm ...
    ciphertext = bytearray(enc_func('A' * 16 + 'AadminAtrue'))
    # comment1=cooking %20MCs;userdata= AAAAAAAAAAAAAAAA ;adminAtrue;comm ...
    ciphertext[32] = ciphertext[32] ^ int.from_bytes(b'A') ^ int.from_bytes(b';')
    #                                         bit flip here    sets bit here
    #                                         v                v
    # comment1=cooking %20MCs;userdata= AAAAAAAAAAAAAAAA ;admin=true;comm ...
    ciphertext[38] = ciphertext[38] ^ int.from_bytes(b'A') ^ int.from_bytes(b'=')
    # 3rd block gets scambled
    # bit flip is propagated to 4th block
    return ciphertext


if __name__ == "__main__":
    # Oracle
    print("Black box:", black_box_ecb_cbc(b'X'*50))
    print()
    # ECB decryption
    enc_func = unknown_string_encrypter()
    block_size = detect_block_size(enc_func)
    print(f"Block size: {block_size}")
    ecb = detect_ecb(enc_func, block_size)
    print(f"ECB detected: {ecb}")
    print()
    # Prepend A's
    for i in [3, 15, 16, 35]:
        text = i * 'B'
        output = (number_of_As(text, 16) - 1) * 'A' + text
        print(output, len(output), f"({i}xB)")
    print()
    # Structured Cookie
    print("Parsed:", parse_kv("foo=bar&baz=qux&zap=zazzle"))
    print("Metachars eaten:", profile_for("foo@bar.com&role=admin"))
    c = CookieServer()
    ciphertext = c.encrypt_profile("foo@bar.com")
    print("Encrypted & decrypted:", parse_kv(c.decrypt_profile(ciphertext)))
    print()
    # CBC bit flip
    prev_block = int.from_bytes(b'C')
    aes_key = int.from_bytes(b'K')
    plaintext = int.from_bytes(b'P')
    ciphertext = plaintext ^ prev_block ^ aes_key
    plaintext = ciphertext ^ aes_key ^ prev_block
    print("Decrypted plaintext before bit flip:", plaintext.to_bytes(), bin(plaintext))
    print("Flipping bits in previous block works:")
    for target in [b'Q', b'R', b'S', b'=', b';']:
        flip = plaintext ^ int.from_bytes(target)
        prev_block_flip = prev_block ^ flip
        plaintext_flip = ciphertext ^ aes_key ^ prev_block_flip
        print(f"Decrypted plaintext after bit flip ({bin(flip)}):", plaintext_flip.to_bytes(), bin(plaintext_flip))
    