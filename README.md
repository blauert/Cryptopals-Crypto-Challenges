https://cryptopals.com/

<details>
<summary>Helper functions output</summary>

```
judge_letter_frequency()
Scores:
b'##$$]ZZXX' -> 2032.6657604320985
b'X-Ray Zulu' -> 1237.1069949999999
b'ETAOIN SHRDLU' -> 276.643918076923

hamming_distance()
Hamming distance: b'this is a test' b'wokka wokka!!!' -> 37

guess_keysize()
Keysize: [1, 2, 3, 1, 2, 3, 1, 2, 3, 1] -> 3

black_box_ecb_cbc()
Encryption mode: ECB
Black box: b'\xc6\xc5\xf1b\xd2\x81q\x91 \xd9@\x81\xefQ\xa46C\x98\x18\x17\x88\x93\xdf\x0e\xa9\xb6\x85\xb6\xd3uf<C\x98\x18\x17\x88\x93\xdf\x0e\xa9\xb6\x85\xb6\xd3uf<\x86\xa0Cl\xe6\n\xdf\xd69\xb3 \x99\xd3V\xae\x00'

detect_ecb()
Block size: 16
ECB detected: True

number_of_As()
AAAAAAAAAAAABBB 15 (3xB)
BBBBBBBBBBBBBBB 15 (15xB)
AAAAAAAAAAAAAAABBBBBBBBBBBBBBBB 31 (16xB)
AAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB 47 (35xB)

CookieServer()
Parsed: {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}
Metachars eaten: email=foo@bar.comroleadmin&uid=10&role=user
Encrypted & decrypted: {'email': 'foo@bar.com', 'uid': '10', 'role': 'user'}

CBC bit flip
Decrypted plaintext before bit flip: b'P' 0b1010000
Flipping bits in previous block works:
Decrypted plaintext after bit flip (0b1): b'Q' 0b1010001
Decrypted plaintext after bit flip (0b10): b'R' 0b1010010
Decrypted plaintext after bit flip (0b11): b'S' 0b1010011
Decrypted plaintext after bit flip (0b1101101): b'=' 0b111101
Decrypted plaintext after bit flip (0b1101011): b';' 0b111011

PaddingServerCBC()
b'ABCDEFGHIJKLMNOPyellow submarine1234\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
b'\xb8\xe7\xd1\x0e\x038\x93z\xb3\x8d\xfeRE\x02\xd8\xdayellow submarin\x01'
ciphertext[15] ^ 100 -> plaintext[31] == \x01
100 ^ \x01 -> plaintext[31] == e (101)

b'Q\nJ\xb2\xeb\x7f\x944\x80\xda\x01\x9e$\x11\xbe\xb6ABCDEFGHIJKLMNOPyellow submarine1234\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
b'+\xc4\xbe&.I\x19\xdbf\xcd\xa7\xfaI\xb5%FABCDEFGHIJKLMNO\x01'
ciphertext[15] ^ 81 -> plaintext[31] == \x01
81 ^ \x01 -> plaintext[31] == P (80)

sum_of_squared_differences()
Letter scores:
'ice ice baby' -> 24.5
'!*§$%&/()=?#' -> 50.0
Trigram scores:
['the', 'ice'] -> 12.2
['xxx', 'zzz'] -> 12.4
```

</details>

<details>
<summary>Solutions (spoiler alert!)</summary>

```
1: Convert hex to base64
b"I'm killing your brain like a poisonous mushroom"
b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

2: Fixed XOR
bytearray(b"the kid don\'t play")
b'746865206b696420646f6e277420706c6179'

3: Single-byte XOR cipher
bytearray(b"Cooking MC\'s like a pound of bacon")

4: Detect single-character XOR
bytearray(b'Now that the party is jumping\n')

5: Implement repeating-key XOR
b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

6: Break repeating-key XOR
bytearray(b'Terminator X: Bring the noise')
I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the m ...

7: AES in ECB mode
I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the m ...

8: Detect AES in ECB mode
3 repeating blocks in line 133: b'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'

9: Implement PKCS#7 padding
b'YELLOW SUBMARINE\x04\x04\x04\x04'

10: Implement CBC mode
Key: b'YELLOW SUBMARINE'
IV: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
Original: bytearray(b' on \nPlay that funky music \n\x04\x04\x04\x04')
Unpadded: bytearray(b' on \nPlay that funky music \n')
I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the m ...

11: An ECB/CBC detection oracle
Encryption mode: CBC
No repeated blocks -> CBC detected!
Encryption mode: CBC
No repeated blocks -> CBC detected!
Encryption mode: ECB
15 repeated blocks -> ECB detected!

12: Byte-at-a-time ECB decryption (Simple)
Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by

13: ECB cut-and-paste
{'email': 'foo@bar.com', 'uid': '10', 'role': 'user'}
{'email': 'xx1337h@ck.er', 'uid': '10', 'role': 'admin', 'rol': 'user'}

14: Byte-at-a-time ECB decryption (Harder)
Length of random prefix: 0
Target bytes start at index: 0
Start configuration: AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAT
Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by

15: PKCS#7 padding validation
b'ICE ICE BABY'
PKCS#7 padding is incorrect.
PKCS#7 padding is incorrect.

16: CBC bitflipping attacks
b'comment1=cooking%20MCs;userdata=\x95c\x9e7A\xb6({\xd3\xde\xfa\xe6X\xa4\xe6\xd6;admin=true;comment2=%20like%20a%20pound%20of%20bacon'
-> Is admin? True

17: The CBC padding oracle
Without IV prepended: he point, to the point, no faking
With IV prepended: 000002Quick to the point, to the point, no faking

18: Implement CTR, the stream cipher mode
Keystream: 76d1cb4bafa246e2e3af035d6c13c372d2ec6cdc986d12decfda1f93afee73182da08ecb117b374bc3dab726b2fc84cdc180ab3549fa6e55d14c6667c96fa5b0
Decrypted counter block 0: 00000000000000000000000000000000
Decrypted counter block 1: 00000000000000000100000000000000
Decrypted counter block 2: 00000000000000000200000000000000
Decrypted counter block 3: 00000000000000000300000000000000
Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby 

19: Break fixed-nonce CTR mode using substitutions
First guess (letter frequencies):      Second guess, refined w/ trigrams:
-------------------------------------- --------------------------------------
i have met them at close of day        i have met them at close of day
coming with vivid faces                coming with vivid faces
from counter or desk among grey        from counter or desk among grey
eighteenth-century houses.             eighteenth-century houses.
i have passed with a nod of the heae   i have passed with a nod of the head
...

20: Break fixed-nonce CTR statistically
Same as challenge 19...
Letters: I'm rated "R"...this is a warning, ya better void / Poets are paranoid, DJ's D-stroyed
Refined: I'm rated "R"...this is a warning, ya better void / Poets are paranoid, DJ's D-stroyed
Letters: Cuz I came back to attack others in spite- / Strike like lightnin', It's quite frightenin'!
Refined: Cuz I came back to attack others in spite- / Strike like lightnin', It's quite frightenin'!
Letters: But don't be afraid in the dark, in a park / Not a scream or a cry, or a bark, more like a sparj;
Refined: But don't be afraid in the dark, in a park / Not a scream or a cry, or a bark, more like a spark;
Letters: Ya tremble like a alcoholic, muscles tighten up / What's that, lighten up! You see a sight but
Refined: Ya tremble like a alcoholic, muscles tighten up / What's that, lighten up! You see a sight but
Letters: Suddenly you feel like your in a horror flick / You grab your heart then wish for tomorrow quicj!
Refined: Suddenly you feel like your in a horror flick / You grab your heart then wish for tomorrow quick!
...
```

</details>