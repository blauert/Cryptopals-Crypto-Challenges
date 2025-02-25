# https://cryptopals.com/sets/4

import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

from set1_helpers import xor_combination

from set4_helpers import (
    exposed_edit,
    CookieServerCTR,
    ctr_bit_flip,
    IVkeyServerCBC,
    sha1_mac,
    verify_mac,
    get_glue_padding,
    extract_sha1_registers,
    LengthExtensionSHA1,
    LengthExtensionMD4,
    md4_mac,
    verify_md4_mac,
    extract_md4_registers,
    get_md4_glue_padding,
    HMACServer,
    TimingAttackClient,
    BetterTimingAttackClient,
)


def ch25():
    # https://cryptopals.com/sets/4/challenges/25
    print('25: Break "random access read/write" AES CTR')
    with open('txt/25.txt') as file:
        ciphertext = base64.b64decode(file.read())
    cipher = AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB)
    plaintext = Padding.unpad(cipher.decrypt(ciphertext), 16)
    # Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key
    key = get_random_bytes(16)
    fixed_nonce = int(0).to_bytes(8)
    e_cipher = AES.new(key, AES.MODE_CTR, nonce=fixed_nonce)
    ctext = e_cipher.encrypt(plaintext)
    # the attacker has the ciphertext and controls the offset and "new text"
    keystream = exposed_edit(ctext, key, 0, b'\x00'*len(ctext))
    # Recover the original plaintext
    plaintext = xor_combination(ctext, keystream)
    print(plaintext[:81])


def ch26():
    # https://cryptopals.com/sets/4/challenges/26
    print("26: CTR bitflipping")
    c = CookieServerCTR()
    print(f"Is admin? -> {c.is_admin(ctr_bit_flip(c.encrypt_string))}")


def ch27():
    # https://cryptopals.com/sets/4/challenges/27
    print("27: Recover the key from CBC with IV=Key")
    c = IVkeyServerCBC()
    # AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
    ctext = c.encrypt_string(b'Lorem ipsum dolor sit amet consectetur adipiscing elit')
    # Modify the message (you are now the attacker): C_1, C_2, C_3 -> C_1, 0, C_1
    modified_ctext = ctext[:16] + b'\x00' * 16 + ctext  # append full ctext C to ensure correct padding
    try:
        c.consume_ciphertext(modified_ctext)
    except Exception as e:
        # this is C1 XORed against the iv (= the key)
        block1 = e.args[0][:16]
        # this is C1 XORed against 0
        block3 = e.args[0][32:48]
    # extract the key: P'_1 XOR P'_3
    key = xor_combination(block1, block3)
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    print(Padding.unpad(cipher.decrypt(ctext), 16))


def ch28():
    # https://cryptopals.com/sets/4/challenges/28
    print("28: Implement a SHA-1 keyed MAC")
    key = get_random_bytes(16)
    message = b'this is my message'
    print("Message:", message)
    mac = sha1_mac(key, message)
    print("MAC:", mac)
    print("Untampered?", verify_mac(key, message, mac))


def ch29():
    # https://cryptopals.com/sets/4/challenges/29
    print("29: Break a SHA-1 keyed MAC using length extension")
    key = get_random_bytes(16)
    original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    original_mac = sha1_mac(key, original_message)
    print(f"Original Message: {original_message}")
    print(f"Original MAC: {original_mac.hex()}")
    print("Untampered?", verify_mac(key, original_message, original_mac))
    # Guess key length
    key_len = 1
    while True:
        print(f"Trying Key Length: {key_len}")
        # Extract SHA-1 internal state
        a, b, c, d, e = extract_sha1_registers(original_mac)
        # Compute glue padding (recreating the padding SHA-1 used)
        glue_padding = get_glue_padding(key_len, original_message)
        # Forge new message
        new_message = b";admin=true"
        forged_message = original_message + glue_padding + new_message
        # Compute forged MAC using extracted state
        forged_length = key_len + len(forged_message)
        forged_mac = LengthExtensionSHA1.sha1(new_message, a, b, c, d, e, forged_length)
        # Verify if the forged MAC is valid
        untampered = verify_mac(key, forged_message, forged_mac)
        print("Untampered?", untampered)
        if untampered:
            print(f"Forged Message: {forged_message}")
            print(f"Forged MAC: {forged_mac.hex()}")
            break
        key_len += 1


def ch30():
    # https://cryptopals.com/sets/4/challenges/30
    print("30: Break an MD4 keyed MAC using length extension")
    key = get_random_bytes(16)
    original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    original_mac = md4_mac(key, original_message)
    print(f"Original Message: {original_message}")
    print(f"Original MAC: {original_mac.hex()}")
    print("Untampered?", verify_md4_mac(key, original_message, original_mac))
    # Try different key lengths (brute force)
    key_len = 1
    while True:
        print(f"Trying Key Length: {key_len}")
        # Extract MD4 internal state from original MAC
        a, b, c, d = extract_md4_registers(original_mac)
        # Compute the glue padding MD4 would have appended to (key || original_message)
        glue_padding = get_md4_glue_padding(key_len, original_message)
        # Forge new message: original_message || glue_padding || new_message
        new_message = b";admin=true"
        forged_message = original_message + glue_padding + new_message
        # Compute the total forged length (in bytes): key length + original_message + glue_padding + new_message
        forged_total_length = key_len + len(original_message) + len(glue_padding) + len(new_message)
        # Compute the forged MAC by processing ONLY new_message
        # using the extracted state and the assumed total length.
        forged_mac = LengthExtensionMD4.md4(new_message, a, b, c, d, forged_total_length)
        # Verify whether the forged MAC is accepted (i.e. matches MD4(key || forged_message))
        untampered = verify_md4_mac(key, forged_message, forged_mac)
        print("Untampered?", untampered)
        if untampered:
            print(f"Forged Message: {forged_message}")
            print(f"Forged MAC: {forged_mac.hex()}")
            break
        key_len += 1


def ch31():
    # https://cryptopals.com/sets/4/challenges/31
    print("31: Implement and break HMAC-SHA1 with an artificial timing leak")
    server = HMACServer(insecure_delay=0.05)  # 50ms
    server.start()  # Start the server in the background
    client = TimingAttackClient()
    recovered_hmac = client.recover_hmac()
    print("Recovered HMAC:", recovered_hmac)
    server.shutdown()  # Shut down the server when done


def ch32():
    # https://cryptopals.com/sets/4/challenges/32
    print("32: Break HMAC-SHA1 with a slightly less artificial timing leak")
    server = HMACServer(insecure_delay=0.005)  # 5ms
    server.start()
    client = TimingAttackClient()
    recovered_hmac = client.recover_hmac()
    print("Recovered HMAC:", recovered_hmac)
    server.shutdown()
    # At some point, the difference will be too small to reliably measure due to network jitter and OS scheduling noise.
    # Improve the attack with multiple timing samples and averaging.
    print("Try again...")
    server.start()
    client = BetterTimingAttackClient(samples_per_byte=10)
    recovered_mac = client.find_valid_mac()
    print(f"Recovered HMAC: {recovered_mac}")
    server.shutdown()


if __name__ == "__main__":
    ch25(), print()
    ch26(), print()
    ch27(), print()
    ch28(), print()
    ch29(), print()
    ch30(), print()
    ch31(), print()
    ch32()