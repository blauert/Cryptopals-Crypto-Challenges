from Crypto.Cipher import AES
from Crypto.Hash import MD4
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

import hmac
import hashlib
import logging
import os
import random
import requests
import struct
import time
import threading

from flask import Flask, request, abort
from werkzeug.serving import make_server


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
    # https://www.youtube.com/watch?v=H_bvdhPMizE
    # https://danq.me/2023/11/30/length-extension-attack/

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


class LengthExtensionMD4:
    """MD4 length extension attack implementation."""

    @staticmethod
    def _left_rotate(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _padding(stream, total_length_bits):
        """
        Pads the given 'stream' (bytes) as MD4 would, assuming the full message length in bits is total_length_bits.
        (total_length_bits is computed on the entire message—that is key || original_message || glue_padding || new_message)
        """
        padded = bytearray(stream)
        padded.append(0x80)
        while (len(padded) % 64) != 56:
            padded.append(0x00)
        padded += struct.pack("<Q", total_length_bits)
        return bytes(padded)

    @staticmethod
    def _process_block(block, a, b, c, d):
        """Process a single 64-byte block with MD4 and update state (a, b, c, d)."""
        # Unpack block into 16 little-endian 32-bit integers
        X = list(struct.unpack("<16I", block))

        # Define MD4 auxiliary functions (with masking to 32 bits)
        def F(x, y, z): 
            return ((x & y) | ((~x) & z)) & 0xFFFFFFFF
        def G(x, y, z): 
            return ((x & y) | (x & z) | (y & z)) & 0xFFFFFFFF
        def H(x, y, z): 
            return (x ^ y ^ z) & 0xFFFFFFFF

        # Each round uses modular additions; force mod 2^32 at each step.
        def round1(a, b, c, d, k, s):
            return LengthExtensionMD4._left_rotate((a + F(b, c, d) + X[k]) & 0xFFFFFFFF, s)
        def round2(a, b, c, d, k, s):
            return LengthExtensionMD4._left_rotate((a + G(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
        def round3(a, b, c, d, k, s):
            return LengthExtensionMD4._left_rotate((a + H(b, c, d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        # Save the initial state.
        aa, bb, cc, dd = a, b, c, d

        # Round 1 (process 16 operations in groups of 4)
        a = round1(a, b, c, d, 0, 3)
        d = round1(d, a, b, c, 1, 7)
        c = round1(c, d, a, b, 2, 11)
        b = round1(b, c, d, a, 3, 19)

        a = round1(a, b, c, d, 4, 3)
        d = round1(d, a, b, c, 5, 7)
        c = round1(c, d, a, b, 6, 11)
        b = round1(b, c, d, a, 7, 19)

        a = round1(a, b, c, d, 8, 3)
        d = round1(d, a, b, c, 9, 7)
        c = round1(c, d, a, b, 10, 11)
        b = round1(b, c, d, a, 11, 19)

        a = round1(a, b, c, d, 12, 3)
        d = round1(d, a, b, c, 13, 7)
        c = round1(c, d, a, b, 14, 11)
        b = round1(b, c, d, a, 15, 19)

        # Round 2
        a = round2(a, b, c, d, 0, 3)
        d = round2(d, a, b, c, 4, 5)
        c = round2(c, d, a, b, 8, 9)
        b = round2(b, c, d, a, 12, 13)

        a = round2(a, b, c, d, 1, 3)
        d = round2(d, a, b, c, 5, 5)
        c = round2(c, d, a, b, 9, 9)
        b = round2(b, c, d, a, 13, 13)

        a = round2(a, b, c, d, 2, 3)
        d = round2(d, a, b, c, 6, 5)
        c = round2(c, d, a, b, 10, 9)
        b = round2(b, c, d, a, 14, 13)

        a = round2(a, b, c, d, 3, 3)
        d = round2(d, a, b, c, 7, 5)
        c = round2(c, d, a, b, 11, 9)
        b = round2(b, c, d, a, 15, 13)

        # Round 3
        a = round3(a, b, c, d, 0, 3)
        d = round3(d, a, b, c, 8, 9)
        c = round3(c, d, a, b, 4, 11)
        b = round3(b, c, d, a, 12, 15)

        a = round3(a, b, c, d, 2, 3)
        d = round3(d, a, b, c, 10, 9)
        c = round3(c, d, a, b, 6, 11)
        b = round3(b, c, d, a, 14, 15)

        a = round3(a, b, c, d, 1, 3)
        d = round3(d, a, b, c, 9, 9)
        c = round3(c, d, a, b, 5, 11)
        b = round3(b, c, d, a, 13, 15)

        a = round3(a, b, c, d, 3, 3)
        d = round3(d, a, b, c, 11, 9)
        c = round3(c, d, a, b, 7, 11)
        b = round3(b, c, d, a, 15, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

        return a, b, c, d

    @staticmethod
    def md4(data, a, b, c, d, total_length_bytes):
        """
        Compute MD4 hash on 'data' (the extension, e.g. new_message) starting from state (a, b, c, d)
        and assuming that the overall (forged) message length in bytes is total_length_bytes.
        """
        total_length_bits = total_length_bytes * 8
        padded_data = LengthExtensionMD4._padding(data, total_length_bits)
        for i in range(0, len(padded_data), 64):
            a, b, c, d = LengthExtensionMD4._process_block(padded_data[i:i+64], a, b, c, d)
        return struct.pack("<4I", a, b, c, d)


def md4_mac(key, message):
    """Computes MD4-based MAC as MD4(key || message)"""
    return MD4.new(key + message).digest()


def verify_md4_mac(key, message, mac):
    """Returns True if the MAC is valid for key || message"""
    return md4_mac(key, message) == mac


def extract_md4_registers(md4_hash):
    """Extract the 4 (32-bit) registers (A, B, C, D) from an MD4 digest"""
    return struct.unpack("<4I", md4_hash)


def get_md4_glue_padding(key_length, message):
    """
    Computes MD4 glue padding for a message that was hashed as:
         MD4(key || message)
    Returns the padding that MD4 would have appended to (key || message).
    """
    total_length = key_length + len(message)
    total_length_bits = total_length * 8
    # MD4 padding: 0x80 then zeros until message length mod 64 == 56,
    # then the 64-bit little-endian representation of (total_length_bits)
    padding = b"\x80"
    padding += b"\x00" * ((56 - (total_length + 1) % 64) % 64)
    padding += struct.pack("<Q", total_length_bits)
    return padding


class HMACServer:
    def __init__(self, host='127.0.0.1', port=9000, insecure_delay=0.05):
        """
        insecure_delay: time in seconds to sleep after comparing each matching byte.
        (Default is 0.05 seconds = 50ms.)
        """
        self.host = host
        self.port = port
        self.insecure_delay = insecure_delay
        # Generate a random secret key for HMAC (fixed while the server is running)
        self.secret_key = os.urandom(16)
        # Create the Flask app
        self.app = Flask(__name__)
        self.setup_routes()
        self.server = None
        self.thread = None

        # Silence the werkzeug logger
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

    def setup_routes(self):
        @self.app.route("/test")
        def test():
            # Get query parameters: file and signature
            file_param = request.args.get("file", "")
            signature_param = request.args.get("signature", "")
            # Compute the valid HMAC-SHA1 for the file parameter.
            valid_hmac = self.compute_hmac_sha1(self.secret_key, file_param.encode())
            # Convert the valid HMAC to a hex string (as bytes) for comparison.
            valid_hmac_hex = valid_hmac.hex().encode()
            self.solution = valid_hmac_hex
            if self.insecure_compare(signature_param.encode(), valid_hmac_hex):
                return "OK", 200
            else:
                abort(500)

    def insecure_compare(self, a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings byte-by-byte.
        Sleep for self.insecure_delay seconds after each matching byte.
        Return False immediately if a byte differs.
        """
        if len(a) != len(b):
            return False
        for x, y in zip(a, b):
            if x != y:
                return False
            time.sleep(self.insecure_delay)
        return True

    def compute_hmac_sha1(self, key: bytes, message: bytes) -> bytes:
        """Compute the HMAC-SHA1 for the given message using the key."""
        return hmac.new(key, message, hashlib.sha1).digest()

    def start(self):
        """Start the Flask server in a background thread."""
        self.server = make_server(self.host, self.port, self.app)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        # Give the server a moment to start
        time.sleep(1)
        print(f"Server started at http://{self.host}:{self.port}")

    def shutdown(self):
        """Shut down the Flask server."""
        if self.server:
            self.server.shutdown()
            self.thread.join()
            print(f"The correct HMAC was {self.solution}")
            print("Server shutdown.")


class TimingAttackClient:
    def __init__(self, target_url="http://127.0.0.1:9000/test", file_param="foo"):
        self.target_url = target_url
        self.file_param = file_param

    def query(self, signature: str) -> float:
        """
        Query the target URL with the provided signature.
        Returns the elapsed time (in seconds) of the request.
        """
        params = {"file": self.file_param, "signature": signature}
        start = time.perf_counter()
        try:
            _ = requests.get(self.target_url, params=params)
        except Exception:
            return 0.0
        end = time.perf_counter()
        return end - start

    def recover_hmac(self) -> str:
        """
        Exploit the timing leak to recover the valid HMAC one hex digit at a time.
        Returns the recovered HMAC (hex-encoded).
        """
        known = ""
        hex_chars = "0123456789abcdef"
        target_length = 40  # HMAC-SHA1 produces 20 bytes = 40 hex characters.
        print("Starting timing attack...")
        while len(known) < target_length:
            timings = {}
            for c in hex_chars:
                # Construct a trial signature: known part + candidate + pad with zeros.
                trial = known + c + "0" * (target_length - len(known) - 1)
                t = self.query(trial)
                timings[c] = t
                print(f"Trying {trial} -> {t:.3f} sec")
            best_char = max(timings, key=timings.get)
            known += best_char
            print(f"Guessed so far: {known}")
        return known


class BetterTimingAttackClient:
    """Performs a timing attack using multiple timing samples and averaging."""

    def __init__(self, target_url="http://127.0.0.1:9000/test", file_param="foo", hmac_length=20, samples_per_byte=5):
        self.target_url = target_url
        self.file_param = file_param
        self.hmac_length = hmac_length  # HMAC-SHA1 is 20 bytes long
        self.samples_per_byte = samples_per_byte  # Number of timing samples per byte

    def measure_response_time(self, signature):
        """Sends a request with a given signature and returns the response time."""
        url = f"{self.target_url}?file={self.file_param}&signature={signature}"
        start_time = time.perf_counter()
        response = requests.get(url)
        end_time = time.perf_counter()
        return (end_time - start_time), response.status_code

    def find_valid_mac(self):
        """Performs the timing attack to discover the valid MAC."""
        discovered_mac = bytearray(self.hmac_length)

        print(f"Starting timing attack with {self.samples_per_byte} samples per byte...")

        for i in range(self.hmac_length):
            best_byte = None
            best_avg_time = 0

            for candidate in range(256):  # Test all possible byte values (0x00 to 0xFF)
                test_mac = discovered_mac[:i] + bytes([candidate]) + b"0" * (self.hmac_length - i - 1)
                test_mac_hex = test_mac.hex()

                sample_times = []
                for _ in range(self.samples_per_byte):
                    response_time, status_code = self.measure_response_time(test_mac_hex)
                    sample_times.append(response_time)

                avg_time = sum(sample_times) / len(sample_times)

                print(f"Testing byte {i}: {candidate:02x}, Avg Time: {avg_time:.6f}")

                if avg_time > best_avg_time:
                    best_avg_time = avg_time
                    best_byte = candidate

            discovered_mac[i] = best_byte
            print(f"Byte {i} found: {best_byte:02x} (Avg Time: {best_avg_time:.6f})")

        print(f"Final discovered MAC: {discovered_mac.hex()}")
        return discovered_mac.hex()


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