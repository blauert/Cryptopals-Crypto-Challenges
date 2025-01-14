import random

from Crypto.Cipher import AES
from Crypto.Util import Padding


class PaddingServerCBC:
    
    def __init__(self):
        self.block_size = 16
        key = random.randbytes(16)
        self.iv = random.randbytes(self.block_size)
        self.e_cipher = AES.new(key, AES.MODE_CBC, iv=self.iv)
        self.d_cipher = AES.new(key, AES.MODE_CBC, iv=self.iv)

    def encrypt_string(self, plaintext):
        return self.iv, self.e_cipher.encrypt(Padding.pad(plaintext, self.block_size))

    def decrypt_string(self, ciphertext):
        return self.d_cipher.decrypt(ciphertext)
    
    def leaky_decrypt(self, ciphertext):
        plaintext = self.decrypt_string(ciphertext)
        # side-channel leak
        try:
            Padding.unpad(plaintext, self.block_size)
            return
        except Exception as e:
            return e


def padding_oracle(ciphertext, padding_func):
    # only block 2 ff. can be decrypted (prepend iv to decrypt 1st block of ciphertext)
    # IVIVIVIVIVIVIVIV CCCCCCCCCCCCCCCC CCCCCCCCCCCCCCCC CCCCCCCCCCCCCCCC
    #                |                |                |
    #                `--------------->`--------------->`--------------->
    #                  PPPPPPPPPPPPPPPP PPPPPPPPPPPPPPPP PPPPPPPPPPPPPPPP
    block_size = 16
    plaintext = bytearray()
    for i in range(0, len(ciphertext)-block_size, block_size):
        # two blocks to work on, 1st gets modified, 2nd gets decrypted
        cur_blocks = bytearray(ciphertext[i:i+2*block_size])
        cur_plaintext = bytearray(block_size)
        # loop backwards over the block's bytes
        for j in range(block_size-1, -1, -1):
            padding_byte = block_size-j
            cur_blocks_padded = cur_blocks.copy()
            # set known bytes to appropriate padding: j=14: ...2, j=13: ...33, j=12: ...444, etc
            for m in range(j+1, block_size):  # no action for j=15
                cur_blocks_padded[m] = cur_blocks[m] ^ cur_plaintext[m] ^ padding_byte
            # block[15] ^ 0 gives false positives for padded blocks (\x02, \x03, etc) but is needed to detect \x01 padding!
            for k in range(255, -1, -1):  # -> solution: check 0 last!
                cur_mod = cur_blocks_padded.copy()
                # j=15: .....x
                # j=14: ....x2  try all x's until padding is correct (no error from padding_func)
                # j=13: ...x33
                cur_mod[j] = cur_mod[j] ^ k
                if padding_func(cur_mod) is None:
                    cur_plaintext[j] = k ^ padding_byte
                    break
        plaintext.extend(cur_plaintext)
    return plaintext


if __name__ == "__main__":
    # CBC padding oracle by hand
    cbc = PaddingServerCBC()
    iv, ciphertext = cbc.encrypt_string(b'ABCDEFGHIJKLMNOPyellow submarine1234')
    for ciphtxt in [ciphertext, iv+ciphertext]:
        print(cbc.decrypt_string(ciphtxt))
        for i in range(255, -1, -1):
            ciph_mod = bytearray(ciphtxt)
            ciph_mod[15] = ciphtxt[15] ^ i
            if cbc.leaky_decrypt(ciph_mod[:32]) is None:
                print(cbc.decrypt_string(ciph_mod[:32]))
                print(f"ciphertext[15] ^ {i} -> plaintext[31] == \\x01")
                print(f"{i} ^ \\x01 -> plaintext[31] == {chr(i ^ 1)} ({i ^ 1})\n")
                break
