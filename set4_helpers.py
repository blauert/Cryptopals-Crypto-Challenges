from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


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