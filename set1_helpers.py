from collections import Counter, defaultdict
from statistics import fmean


def xor_combination(buf1, buf2):
    result = bytearray()
    for b in zip(buf1, buf2):
        result.append(b[0] ^ b[1])
    return result


def judge_letter_frequency(message):
    english_letter_frequencies = {
        ' ': 20, # space has around 20% probability
        # https://en.wikipedia.org/wiki/Letter_frequency
        'e': 12.702, 't': 9.056, 'a': 8.167, 'o': 7.507, 'i': 6.966, 'n': 6.749, 's': 6.327, 'h': 6.094, 'r': 5.987,
        'd': 4.253, 'l': 4.025, 'c': 2.782, 'u': 2.758, 'm': 2.406, 'w': 2.360, 'f': 2.228, 'g': 2.015, 'y': 1.974,
        'p': 1.929, 'b': 1.492, 'v': 0.978, 'k': 0.772, 'j': 0.153, 'x': 0.150, 'q': 0.095, 'z': 0.074
    }
    char_counts = Counter(message.decode("ascii", errors="ignore").lower())
    score = 0
    for letter in english_letter_frequencies:
        frequency = 100 / len(message) * char_counts.get(letter, 0)
        # sum of squared differences
        score += (english_letter_frequencies.get(letter) - frequency)**2
    return score


def decypher_single_byte_xor(string):
    results = {}
    for ascii_char in range(128):
        result = bytearray()
        for b in string:
            result.append(b ^ ascii_char)
        results[ascii_char] = result
    scores = []
    for char, result in results.items():
        # (score, char, result)
        scores.append((judge_letter_frequency(result), char, result))
    # return lowest scoring result
    scores.sort()
    return scores[0]


def repeating_key_xor(text, key):
    # the inverse of XOR is XOR, to this works both ways
    i = 0
    result = bytearray()
    for letter in text:
        result.append(letter ^ key[i])
        i = (i+1) % len(key)
    return result


def hamming_distance(str1, str2):
    # number of differing bits
    count = 0
    for b in zip(str1, str2):
        count += bin(b[0] ^ b[1]).count('1')
    return count


def guess_keysize(ciphertext):
    MAX_KEYSIZE = 40
    MAX_BLOCKS = 10
    # Split text into blocks
    keysizes_blocks = defaultdict(list)
    for keysize in range(2, min(len(ciphertext), MAX_KEYSIZE)+1):
        num_blocks = min(MAX_BLOCKS, len(ciphertext)//keysize)
        # take at least two keysize blocks
        if num_blocks >= 2:
            for b in range(num_blocks):
                    keysizes_blocks[keysize].append(ciphertext[b*keysize : (b+1)*keysize])
    # Find edit distances
    edit_distances = {}
    for keysize, blocks in keysizes_blocks.items():
        cur_distances = []
        for i in range(len(blocks[1:])):
            this_block, prev_block = blocks[i], blocks[i-1]
            dist = hamming_distance(this_block, prev_block)
            # Normalize this result by dividing by KEYSIZE
            normalized_dist = dist / len(this_block)
            cur_distances.append(normalized_dist)
        # average the distances
        edit_distances[keysize] = fmean(cur_distances)
    # Smallest edit distance is the key
    smallest_keysize = min(edit_distances, key=edit_distances.get)
    return smallest_keysize


def break_vigenere_key(ciphertext, keysize):
    # transpose the blocks
    transposed = [bytearray() for _ in range(keysize)]
    i = 0
    for char in ciphertext:
        transposed[i].append(char)
        i = (i+1) % keysize
    key = bytearray()
    for block in transposed:
        _, char, _ = decypher_single_byte_xor(block)
        key.append(char)
    return key


if __name__ == "__main__":
    # Letter frequency
    print("judge_letter_frequency()")
    not_english, english, more_english = b"##$$]ZZXX", b"X-Ray Zulu", b"ETAOIN SHRDLU"
    print("Scores:")
    print(not_english, "->", judge_letter_frequency(not_english))
    print(english, "->", judge_letter_frequency(english))
    print(more_english, "->", judge_letter_frequency(more_english))
    print()
    # Hamming Distance
    print("hamming_distance()")
    str1, str2 = b"this is a test", b"wokka wokka!!!"
    print("Hamming distance:", str1, str2, "->", hamming_distance(str1, str2))
    print()
    # Keysize
    print("guess_keysize()")
    test_input = [1, 2, 3, 1, 2, 3, 1, 2, 3, 1]
    print("Keysize:", test_input, "->", guess_keysize(test_input))