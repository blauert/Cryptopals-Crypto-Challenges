from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

import hashlib
import random


def exposed_edit(ciphertext, key, offset, newtext):
    fixed_nonce = int(0).to_bytes(8)
    d_cipher = AES.new(key, AES.MODE_CTR, nonce=fixed_nonce)
    e_cipher = AES.new(key, AES.MODE_CTR, nonce=fixed_nonce)
    plaintext = bytearray(d_cipher.decrypt(ciphertext))
    plaintext[offset:offset + len(newtext)] = newtext
    new_ciphertext = e_cipher.encrypt(plaintext)
    return new_ciphertext


class CookieServerCTR:
    
    def __init__(self):
        key = get_random_bytes(16)
        fixed_nonce = int(0).to_bytes(8)
        self.d_cipher = AES.new(key, AES.MODE_CTR, nonce=fixed_nonce)
        self.e_cipher = AES.new(key, AES.MODE_CTR, nonce=fixed_nonce)

    def encrypt_string(self, user_input):
        user_input = user_input.replace(';', '";"').replace('=', '"="')
        new_string = f"comment1=cooking%20MCs;userdata={user_input};comment2=%20like%20a%20pound%20of%20bacon"
        return self.e_cipher.encrypt(new_string.encode())

    def decrypt_string(self, ciphertext):
        return self.d_cipher.decrypt(ciphertext)
    
    def is_admin(self, ciphertext):
        plaintext = self.decrypt_string(ciphertext).decode(errors='ignore')
        print(plaintext)
        if ";admin=true;" in plaintext:
            return True
        else:
            return False


def ctr_bit_flip(enc_func):
    ciphertext = bytearray(enc_func('AadminAtrue'))
    #                                   v
    # comment1=cooking %20MCs;userdata= ;adminAtrue;comm ...
    ciphertext[32] = ciphertext[32] ^ int.from_bytes(b'A') ^ int.from_bytes(b';')
    #                                         v
    # comment1=cooking %20MCs;userdata= ;admin=true;comm ...
    ciphertext[38] = ciphertext[38] ^ int.from_bytes(b'A') ^ int.from_bytes(b'=')
    return ciphertext


class IVkeyServerCBC:
    
    def __init__(self):
        self.block_size = 16
        key = get_random_bytes(16)
        # repurpose the key for CBC encryption as the IV
        self.e_cipher = AES.new(key, AES.MODE_CBC, iv=key)
        self.d_cipher = AES.new(key, AES.MODE_CBC, iv=key)

    def encrypt_string(self, user_input):
        return self.e_cipher.encrypt(Padding.pad(user_input, self.block_size))

    def consume_ciphertext(self, ciphertext):
        plaintext = Padding.unpad(self.d_cipher.decrypt(ciphertext), self.block_size)
        allowed_chars = set(chr(i) for i in range(32,127))
        for byte in plaintext:
            # Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext
            if chr(byte) not in allowed_chars:
                raise Exception(plaintext)


class SHA1:
    # https://github.com/pcaro90/Python-SHA1/blob/master/SHA1.py

    def _ROTL(n, x, w=32):
        return ((x << n) | (x >> (w - n))) & 0xFFFFFFFF

    def _padding(stream):
        """Pads the input to be a multiple of 64 bytes, including length encoding."""
        l = len(stream) * 8
        stream += b'\x80'  # Append 1 bit followed by 0s
        stream += b'\x00' * ((56 - (len(stream) % 64)) % 64)
        stream += l.to_bytes(8, 'big')  # Append original length in bits
        return stream

    def _prepare(stream):
        """Break message into 512-bit blocks (16 words of 32 bits each)."""
        return [list(int.from_bytes(stream[i + j:i + j + 4], 'big') for j in range(0, 64, 4)) for i in range(0, len(stream), 64)]

    def sha1(data):
        """Compute SHA-1 hash of input bytes."""
        H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        MASK = 0xFFFFFFFF

        data = SHA1._padding(data)
        blocks = SHA1._prepare(data)

        for block in blocks:
            W = block + [0] * 64
            for t in range(16, 80):
                W[t] = SHA1._ROTL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])

            a, b, c, d, e = H

            for t in range(80):
                if t <= 19:
                    K, f = 0x5A827999, (b & c) | (~b & d)
                elif t <= 39:
                    K, f = 0x6ED9EBA1, b ^ c ^ d
                elif t <= 59:
                    K, f = 0x8F1BBCDC, (b & c) | (b & d) | (c & d)
                else:
                    K, f = 0xCA62C1D6, b ^ c ^ d

                T = (SHA1._ROTL(5, a) + f + e + K + W[t]) & MASK
                e, d, c, b, a = d, c, SHA1._ROTL(30, b), a, T

            H = [(x + y) & MASK for x, y in zip(H, [a, b, c, d, e])]

        return b''.join(h.to_bytes(4, 'big') for h in H)

    def hexdigest(data):
        """Compute SHA-1 hash and return as a hex string."""
        return SHA1.sha1(data).hex()


def sha1_mac(key, message):
    return SHA1.sha1(key + message)


def verify_mac(key, message, mac):
    return mac == SHA1.sha1(key + message)


def get_glue_padding(key_len, message):
    # compute the MD padding of an arbitrary message
    total_length = key_len + len(message)
    return SHA1._padding(b'A' * total_length)[total_length:]


def extract_sha1_registers(mac):
    """Extract SHA-1 registers (a, b, c, d, e) from a given MAC."""
    # Split MAC into 5 registers of 4 bytes each
    return [int.from_bytes(mac[i:i+4], 'big') for i in range(0, 20, 4)]


class LengthExtensionSHA1:
    @staticmethod
    def _ROTL(n, x, w=32):
        return ((x << n) | (x >> (w - n))) & 0xFFFFFFFF

    @staticmethod
    def _padding(stream, total_length_bits):
        """Pad the input to 64 bytes, using the specified total length (in bits)."""
        # Start with the original message
        padded = bytearray(stream)
        # Append 0x80 byte (10000000 in binary)
        padded.append(0x80)
        # Append 0 ≤ k < 512 bits (0 ≤ k < 64 bytes) so that total length is 56 mod 64
        while (len(padded) % 64) != 56:
            padded.append(0x00)
        # Append original length in bits as 64-bit big-endian integer
        padded += total_length_bits.to_bytes(8, 'big')
        return bytes(padded)

    @staticmethod
    def _prepare(stream):
        """Break padded message into 512-bit blocks (16 words of 32 bits each)."""
        return [
            [
                int.from_bytes(stream[i + j : i + j + 4], 'big')
                for j in range(0, 64, 4)
            ]
            for i in range(0, len(stream), 64)
        ]

    @staticmethod
    def sha1(data, a, b, c, d, e, total_length_bytes):
        """
        Compute SHA-1 hash with custom initial state and total length.
        
        Parameters:
        - data: Bytes to process (glue_padding + new_message)
        - a, b, c, d, e: Initial SHA-1 state (from original MAC)
        - total_length_bytes: Total length of the entire forged message (key + original_message + glue_padding + new_message)
        """
        H = [a, b, c, d, e]
        MASK = 0xFFFFFFFF

        # Calculate total length in bits for padding
        total_length_bits = total_length_bytes * 8

        # Apply padding to the data using the total forged length
        padded_data = LengthExtensionSHA1._padding(data, total_length_bits)
        blocks = LengthExtensionSHA1._prepare(padded_data)

        for block in blocks:
            W = block + [0] * 64
            # Expand the message schedule
            for t in range(16, 80):
                W[t] = LengthExtensionSHA1._ROTL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])

            # Initialize working variables
            a_, b_, c_, d_, e_ = H

            # Main loop
            for t in range(80):
                if t <= 19:
                    K = 0x5A827999
                    f = (b_ & c_) | (~b_ & d_)
                elif t <= 39:
                    K = 0x6ED9EBA1
                    f = b_ ^ c_ ^ d_
                elif t <= 59:
                    K = 0x8F1BBCDC
                    f = (b_ & c_) | (b_ & d_) | (c_ & d_)
                else:
                    K = 0xCA62C1D6
                    f = b_ ^ c_ ^ d_

                T = (LengthExtensionSHA1._ROTL(5, a_) + f + e_ + K + W[t]) & MASK
                e_, d_, c_, b_, a_ = d_, c_, LengthExtensionSHA1._ROTL(30, b_), a_, T

            # Update state
            H = [
                (H[0] + a_) & MASK,
                (H[1] + b_) & MASK,
                (H[2] + c_) & MASK,
                (H[3] + d_) & MASK,
                (H[4] + e_) & MASK,
            ]

        return b''.join(h.to_bytes(4, 'big') for h in H)


if __name__ == "__main__":
    # Exposed CTR Edit API
    print("exposed_edit()")
    key = b'YELLOW SUBMARINE'
    fixed_nonce = int(0).to_bytes(8)
    e_cipher = AES.new(key, AES.MODE_CTR, nonce=fixed_nonce)
    d_cipher = AES.new(key, AES.MODE_CTR, nonce=fixed_nonce)
    ptext = b'ICE ICE BABY'
    print(ptext)
    ctext = e_cipher.encrypt(ptext)
    print(ctext)
    new_ctext = exposed_edit(ctext, key, 8, b'HACK')
    print(new_ctext)
    print(d_cipher.decrypt(new_ctext))
    print()
    # SHA-1
    print("SHA1.sha1(msg) == hashlib.sha1(msg).digest()")
    for _ in range(5):
        msg = get_random_bytes(random.randint(1, 1000))
        print(SHA1.sha1(msg) == hashlib.sha1(msg).digest())
    print("https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values")
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
    print(f'"abc" -> A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D')
    print(SHA1.hexdigest(b'abc'))
    print(f'"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" -> 84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1')
    print(SHA1.hexdigest(b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))