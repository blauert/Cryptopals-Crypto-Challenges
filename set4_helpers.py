from Crypto.Cipher import AES


def exposed_edit(ciphertext, key, offset, newtext):
    fixed_nonce = int(0).to_bytes(8)
    d_cipher = AES.new(key, AES.MODE_CTR, nonce=fixed_nonce)
    e_cipher = AES.new(key, AES.MODE_CTR, nonce=fixed_nonce)
    plaintext = bytearray(d_cipher.decrypt(ciphertext))
    plaintext[offset:offset + len(newtext)] = newtext
    new_ciphertext = e_cipher.encrypt(plaintext)
    return new_ciphertext


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
