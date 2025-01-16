from collections import Counter
from itertools import zip_longest

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

from set1_helpers import xor_combination


class PaddingServerCBC:
    
    def __init__(self):
        self.block_size = 16
        key = get_random_bytes(16)
        self.iv = get_random_bytes(self.block_size)
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


def poetry_frequencies():
    with open('set3_english_poetry.txt') as file:
        unique_lines = set(file.read().split('\n'))
    letters = Counter()
    trigrams = Counter()
    for line in unique_lines:
        letters += Counter(line.lower())
        trigrams_cur = []
        for i in range(len(line)-2):
            trigrams_cur.append(line[i:i+3].lower())
        trigrams += Counter(trigrams_cur)
    letter_frequencies = {letter: (count/letters.total())*100 for letter, count in letters.items()}
    trigram_frequencies = {trigram: (count/trigrams.total())*100 for trigram, count in trigrams.items()}
    return letter_frequencies, trigram_frequencies


def sum_of_squared_differences(text, expected_frequencies, alpha=1):
    # Comparing lowercase only gives better result for short data
    counts = Counter([elem.lower() for elem in text])
    total_count = counts.total()
    # Laplace Smoothing to avoid zero probabilities for data not in expected_frequencies
    all_keys = set(expected_frequencies.keys()) | counts.keys()
    smoothed_total = total_count + alpha * len(all_keys)
    # Calculate scores
    score = 0
    for key in all_keys:
        observed_frequency = ((counts.get(key, 0) + alpha) / smoothed_total) * 100
        expected_frequency = expected_frequencies.get(key, 0)
        score += (expected_frequency - observed_frequency) ** 2
    # Normalize score (to account for smaller sample sizes)
    return score / (total_count if total_count > 0 else 1)


def ctr_attack(encrypted_lines):
    # PLAINTEXT-BYTE XOR KEYSTREAM-BYTE = CIPHERTEXT-BYTE
    # CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
    # CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE
    en_letters, en_trigrams = poetry_frequencies()
    allowed_chars = set(chr(i) for i in range(32,127)) | {chr(10), chr(13)}

    # Letter frequencies
    first_candidates = []
    x = 5
    x_best_candidates = []
    for i, chars in enumerate(zip_longest(*encrypted_lines)):
        candidates = []
        for j in range(256):
            cur = [chr(c ^ j) for c in chars if c is not None]
            if set(cur).issubset(allowed_chars):
                score = sum_of_squared_differences(cur, en_letters, alpha=5)  # adjust alpha for better results
                candidates.append(dict(letter_score=score, i=i, key=j))
        candidates.sort(key=lambda x: x['letter_score'])
        first_candidates.append(candidates[0])
        x_best_candidates.append(candidates[:x])
    first_keystream_guess = bytearray(cand['key'] for cand in first_candidates)

    # Trigram frequencies
    trigram_keystream = []
    for i in range(len(x_best_candidates)):
        trigram_scores = []
        for c1 in x_best_candidates[i-2] if i >= 2 else [{'key': 0}]:
            for c2 in x_best_candidates[i-1] if i >= 1 else [{'key': 0}]:
                for c3 in x_best_candidates[i]:
                    # Build the trigram guess
                    key_guess = bytearray([c1['key'], c2['key'], c3['key']])
                    trigrams = []
                    for line in encrypted_lines:
                        if len(line) > i:
                            tri = xor_combination(line[i-2:i+1], key_guess).decode('utf-8')
                            if set(tri).issubset(allowed_chars):
                                trigrams.append(tri)
                    # Calculate trigram score
                    score = sum_of_squared_differences(trigrams, en_trigrams, alpha=50)  # adjust alpha for better results
                    # this only saves the score for c3, but that's enough in this case
                    trigram_scores.append(dict(trigram_score=score, key=c3['key']))
        # Choose the best candidate for this position
        if trigram_scores:
            trigram_scores.sort(key=lambda x: x['trigram_score'])
            trigram_keystream.append(trigram_scores[0]['key'])
        else:
            trigram_keystream.append(0)  # Default to 0 if no valid trigrams
    trigram_keystream = bytearray(trigram_keystream)

    return first_keystream_guess, trigram_keystream


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
    # Letter and trigram frequencies
    letters, trigrams = poetry_frequencies()
    print("Letter scores:")
    print("'ice ice baby' ->", round(sum_of_squared_differences('ice ice baby', letters), 1))
    print("'!*§$%&/()=?#' ->", round(sum_of_squared_differences('!*§$%&/()=?#', letters), 1))
    print("Trigram scores:")
    print("['the', 'ice'] ->", round(sum_of_squared_differences(['the', 'ice'], trigrams), 1))
    print("['xxx', 'zzz'] ->", round(sum_of_squared_differences(['xxx', 'zzz'], trigrams), 1))
    print()